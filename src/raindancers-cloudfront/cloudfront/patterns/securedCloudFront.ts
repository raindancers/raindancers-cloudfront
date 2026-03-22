import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_secretsmanager as secretsmanager,
  aws_kms as kms,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_ssm as ssm,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';
import { AuthSecurityTable } from '../authSecurityTable';
import { FunctionComposer } from '../cloudfront-functions/function-composer';

export enum Extension {
  REQUIRE_AUTH = 'REQUIRE_AUTH',
  REQUIRE_TLS_13 = 'REQUIRE_TLS_13',
  REWRITE_TO_INDEX_HTML = 'REWRITE_TO_INDEX_HTML',
}

export enum RoleMatchMode {
  OR = 'OR',
  AND = 'AND',
}

export interface ExtensionConfig<TRole extends string = string> {
  readonly requiredRoles?: readonly TRole[];
  readonly roleMatchMode?: RoleMatchMode;
}

export interface AddBehaviorOptions<TRole extends string = string> {
  readonly extensions?: Extension[];
  readonly extensionConfig?: ExtensionConfig<TRole>;
  readonly behaviorOptions?: Omit<cloudfront.BehaviorOptions, 'origin'>;
}

export interface CloudFrontWithAzureAuthSplitProps<TRole extends string = string> {
  readonly defaultBehavior: Omit<cloudfront.BehaviorOptions, 'functionAssociations'>;
  readonly additionalBehaviors?: Record<string, Omit<cloudfront.BehaviorOptions, 'edgeLambdas'>>;
  readonly domainNames: string[];
  readonly certificate: any;
  readonly redirectUri?: string;
  readonly webAclId?: string;
  readonly hmacSecretRotationSchedule?: core.Duration;
  readonly securityAlertsTopicArn?: string;
  readonly sessionRevocationTopicArn?: string;
  readonly autoRevokeOnReuse?: boolean;
  readonly jwtClaimsWhitelist?: string[];
  readonly auditLogRetentionDays?: number;
  readonly auditArchiveRetentionDays?: number;
  readonly authSsmParamPrefix: string;
  readonly authRegion: string;
  readonly createOAuthCallback?: boolean;
  readonly defaultExtensions?: Extension[];
  readonly defaultExtensionConfig?: ExtensionConfig<TRole>;
  readonly defaultRootObject?: string;
  readonly errorResponsePagePath?: string;
  readonly enableUserInfoInjection?: boolean;
  readonly userInfoNameFields?: string[];
}

export class SecuredCloudFront<TRole extends string = string> extends constructs.Construct {

  public readonly distribution: cloudfront.Distribution;
  public readonly configSecret: secretsmanager.ISecret;
  public readonly secretArn: string;
  public readonly kmsKey: kms.IKey;
  public readonly authSecurityTable: AuthSecurityTable;
  public readonly auditLogArchive: any;
  public readonly lambdaEdgeRole: iam.Role;
  private readonly authCheckFunction: cloudfront.Function;
  private readonly userInfoFunction?: cloudfront.Function;
  private readonly functionComposer: FunctionComposer;
  private readonly composedFunctions: Map<string, cloudfront.Function>;
  private lastCreatedFunction: cloudfront.Function | undefined;
  private readonly tlsOriginRequestPolicy: cloudfront.OriginRequestPolicy;
  private readonly tenantId: string;
  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly kvs: cloudfront.IKeyValueStore;

  constructor(scope: constructs.Construct, id: string, props: CloudFrontWithAzureAuthSplitProps<TRole>) {
    super(scope, id);

    const redirectUri = this.determineRedirectUri(props.redirectUri, props.domainNames);

    const p = props.authSsmParamPrefix;
    const configSecretArn = ssm.StringParameter.valueForStringParameter(this, `${p}/configSecretArn`);
    const kmsKeyArn = ssm.StringParameter.valueForStringParameter(this, `${p}/kmsKeyArn`);
    const authTableArn = ssm.StringParameter.valueForStringParameter(this, `${p}/authTableArn`);
    const kvsArn = ssm.StringParameter.valueForStringParameter(this, `${p}/kvsArn`);
    const tenantId = ssm.StringParameter.valueForStringParameter(this, `${p}/tenantId`);
    const clientId = ssm.StringParameter.valueForStringParameter(this, `${p}/clientId`);
    const oauth2CallbackRoleName = ssm.StringParameter.valueForStringParameter(this, `${p}/oauth2CallbackRoleName`);

    this.configSecret = secretsmanager.Secret.fromSecretCompleteArn(this, 'ImportedSecret', configSecretArn);
    this.kmsKey = kms.Key.fromKeyArn(this, 'ImportedKey', kmsKeyArn);
    this.authSecurityTable = { table: { tableArn: authTableArn } } as any;
    this.auditLogArchive = null;
    this.secretArn = configSecretArn;

    this.lambdaEdgeRole = new iam.Role(this, 'LambdaEdgeRole', {
      roleName: oauth2CallbackRoleName,
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // we need to add these directly, rather than use grant methods, to avoid circular dependnacies.
    this.lambdaEdgeRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
      resources: [configSecretArn],
    }));

    this.lambdaEdgeRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['kms:Decrypt'],
      resources: [kmsKeyArn],
    }));

    this.lambdaEdgeRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query', 'dynamodb:Scan', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem'],
      resources: [authTableArn],
    }));

    this.lambdaEdgeRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sts:GetWebIdentityToken'],
      resources: ['*'],
    }));

    const kvs = cloudfront.KeyValueStore.fromKeyValueStoreArn(this, 'KVS', kvsArn);
    this.kvs = kvs;
    this.tenantId = tenantId;
    this.clientId = clientId;
    this.redirectUri = redirectUri;

    const configPyContent = `# Generated configuration
import json
import boto3
import os
import logging

logger = logging.getLogger()

# Secret name and region - these must be concrete values, not CloudFormation tokens
# The secret name is constructed from the domain name
CONFIG_SECRET_NAME = 'cloudfront-auth-config-${props.domainNames[0]}'
CONFIG_REGION = '${props.authRegion}'

def get_config():
    logger.info(f'Attempting to load config from Secrets Manager')
    logger.info(f'CONFIG_SECRET_NAME: {CONFIG_SECRET_NAME}')
    logger.info(f'CONFIG_REGION: {CONFIG_REGION}')
    try:
        client = boto3.client('secretsmanager', region_name=CONFIG_REGION)
        response = client.get_secret_value(SecretId=CONFIG_SECRET_NAME)
        return json.loads(response['SecretString'])
    except Exception as e:
        logger.error(f'Failed to get secret. Name="{CONFIG_SECRET_NAME}", Region="{CONFIG_REGION}"')
        logger.error(f'Error: {str(e)}')
        raise
`;

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-auth-'));
    const configPyPath = path.join(tempDir, 'config_generated.py');
    fs.writeFileSync(configPyPath, configPyContent);

    const oauthCallbackFunction = new cloudfront.experimental.EdgeFunction(this, 'OAuthCallback', {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'oauth-callback.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/edge-auth'), {
        bundling: {
          image: lambda.Runtime.PYTHON_3_11.bundlingImage,
          command: [
            'bash', '-c',
            'pip install -r requirements.txt -t /asset-output && ' +
            'cp -r . /asset-output && ' +
            'cp /tmp/config_generated.py /asset-output/config_generated.py',
          ],
          volumes: [
            {
              hostPath: configPyPath,
              containerPath: '/tmp/config_generated.py',
            },
          ],
        },
      }),
      timeout: core.Duration.seconds(30),
      memorySize: 128,
      role: this.lambdaEdgeRole,
    });

    const authCheckCode = this.loadAndReplaceAuthCheckCode(
      tenantId,
      clientId,
      redirectUri,
    );

    this.authCheckFunction = new cloudfront.Function(this, 'AuthCheck', {
      code: cloudfront.FunctionCode.fromInline(authCheckCode),
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      keyValueStore: kvs,
      comment: 'verifies tokens',
    });
    this.lastCreatedFunction = this.authCheckFunction;

    // Create user info endpoint function if enabled
    if (props.enableUserInfoInjection !== false) {
      if (!props.userInfoNameFields || props.userInfoNameFields.length === 0) {
        throw new Error('userInfoNameFields must be provided when enableUserInfoInjection is true');
      }
      const userInfoCode = this.loadAndReplaceUserInfoCode(props.userInfoNameFields);
      this.userInfoFunction = new cloudfront.Function(this, 'UserInfoEndpoint', {
        code: cloudfront.FunctionCode.fromInline(userInfoCode),
        runtime: cloudfront.FunctionRuntime.JS_2_0,
        keyValueStore: kvs,
        comment: 'Returns user info JSON from JWT',
      });
      this.userInfoFunction.node.addDependency(this.authCheckFunction);
      this.lastCreatedFunction = this.userInfoFunction;
    }

    const additionalBehaviors: Record<string, cloudfront.BehaviorOptions> = {};

    if (props.createOAuthCallback !== false) {
      additionalBehaviors['/oauth2/callback'] = {
        origin: props.defaultBehavior.origin,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        ...props.additionalBehaviors?.['/oauth2/callback'],
        edgeLambdas: [{
          functionVersion: oauthCallbackFunction.currentVersion,
          eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
        }],
        cachePolicy: props.additionalBehaviors?.['/oauth2/callback']?.cachePolicy ?? new cloudfront.CachePolicy(this, 'CallbackCachePolicy', {
          cachePolicyName: `${core.Stack.of(this).stackName}-oauth-callback`,
          comment: 'Cache policy for OAuth callback with state cookie forwarding',
          defaultTtl: core.Duration.seconds(0),
          minTtl: core.Duration.seconds(0),
          maxTtl: core.Duration.seconds(1),
          cookieBehavior: cloudfront.CacheCookieBehavior.allowList('oauth_state'),
          headerBehavior: cloudfront.CacheHeaderBehavior.none(),
          queryStringBehavior: cloudfront.CacheQueryStringBehavior.all(),
          enableAcceptEncodingGzip: false,
          enableAcceptEncodingBrotli: false,
        }),
      };
    }

    if (props.additionalBehaviors) {
      Object.entries(props.additionalBehaviors).forEach(([path, behavior]) => {
        if (path !== '/oauth2/callback') {
          additionalBehaviors[path] = behavior;
        }
      });
    }

    // Origin request policy that forwards CloudFront-Viewer-TLS header (required for REQUIRE_TLS_13)
    this.tlsOriginRequestPolicy = new cloudfront.OriginRequestPolicy(this, 'TlsOriginRequestPolicy', {
      headerBehavior: cloudfront.OriginRequestHeaderBehavior.allowList('CloudFront-Viewer-TLS'),
      cookieBehavior: cloudfront.OriginRequestCookieBehavior.none(),
      queryStringBehavior: cloudfront.OriginRequestQueryStringBehavior.none(),
    });

    // Initialize function composer
    this.functionComposer = new FunctionComposer();
    this.composedFunctions = new Map();

    this.distribution = new cloudfront.Distribution(this, 'Distribution', {
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2025,
      defaultBehavior: (() => {
        const defaultBuilt = this.buildFunctionAssociations(props.defaultExtensions, props.defaultExtensionConfig);
        return {
          ...props.defaultBehavior,
          functionAssociations: defaultBuilt?.functionAssociations,
          originRequestPolicy: defaultBuilt?.originRequestPolicy,
        };
      })(),
      additionalBehaviors: additionalBehaviors,
      domainNames: props.domainNames,
      certificate: props.certificate,
      webAclId: props.webAclId,
      defaultRootObject: props.defaultRootObject ?? 'index.html',
      errorResponses: [
        {
          httpStatus: 403,
          responseHttpStatus: 200,
          responsePagePath: props.errorResponsePagePath ?? '/error.html',
          ttl: core.Duration.minutes(5),
        },
        {
          httpStatus: 404,
          responseHttpStatus: 200,
          responsePagePath: props.errorResponsePagePath ?? '/error.html',
          ttl: core.Duration.minutes(5),
        },
        {
          httpStatus: 500,
          responseHttpStatus: 200,
          responsePagePath: props.errorResponsePagePath ?? '/error.html',
          ttl: core.Duration.seconds(10),
        },
        {
          httpStatus: 502,
          responseHttpStatus: 200,
          responsePagePath: props.errorResponsePagePath ?? '/error.html',
          ttl: core.Duration.seconds(10),
        },
        {
          httpStatus: 503,
          responseHttpStatus: 200,
          responsePagePath: props.errorResponsePagePath ?? '/error.html',
          ttl: core.Duration.seconds(10),
        },
        {
          httpStatus: 504,
          responseHttpStatus: 200,
          responsePagePath: props.errorResponsePagePath ?? '/error.html',
          ttl: core.Duration.seconds(10),
        },
      ],
    });

    // Add /userinfo behavior if user info endpoint is enabled
    if (this.userInfoFunction) {
      this.distribution.addBehavior('/userinfo', props.defaultBehavior.origin, {
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        functionAssociations: [
          {
            function: this.userInfoFunction,
            eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
          },
        ],
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      });
    }
  }

  public addBehavior(
    pathPattern: string,
    origin: cloudfront.IOrigin,
    options: AddBehaviorOptions<TRole> | cloudfront.BehaviorOptions = {},
    applyAuth?: boolean,
  ): void {
    // Support legacy signature: addBehavior(path, behaviorOptions, applyAuth)
    if ('origin' in options || 'viewerProtocolPolicy' in options) {
      const behaviorOptions = options as cloudfront.BehaviorOptions;
      const shouldApplyAuth = applyAuth !== false;

      if (shouldApplyAuth) {
        const functionAssociations: cloudfront.FunctionAssociation[] = [
          ...(behaviorOptions.functionAssociations || []),
          {
            function: this.authCheckFunction,
            eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
          },
        ];
        this.distribution.addBehavior(pathPattern, origin, {
          ...behaviorOptions,
          functionAssociations: functionAssociations,
        });
      } else {
        this.distribution.addBehavior(pathPattern, origin, behaviorOptions);
      }
      return;
    }

    // New signature: addBehavior(path, origin, AddBehaviorOptions)
    const addBehaviorOptions = options as AddBehaviorOptions<TRole>;

    const built = this.buildFunctionAssociations(
      addBehaviorOptions.extensions,
      addBehaviorOptions.extensionConfig,
    );

    this.distribution.addBehavior(pathPattern, origin, {
      ...addBehaviorOptions.behaviorOptions,
      functionAssociations: built?.functionAssociations ?? addBehaviorOptions.behaviorOptions?.functionAssociations,
      originRequestPolicy: built?.originRequestPolicy ?? addBehaviorOptions.behaviorOptions?.originRequestPolicy,
    });
  }

  private buildFunctionAssociations(
    extensions?: Extension[],
    config?: ExtensionConfig<TRole>,
  ): { functionAssociations: cloudfront.FunctionAssociation[]; originRequestPolicy?: cloudfront.OriginRequestPolicy } | undefined {
    if (!extensions || extensions.length === 0) {
      return undefined;
    }

    // Generate cache key for this combination of extensions + config
    const cacheKey = this.generateFunctionCacheKey(extensions, config);

    // Check if we already created this function
    let func = this.composedFunctions.get(cacheKey);
    if (!func) {
      // Generate combined function code with Azure AD configuration
      const code = this.functionComposer.compose(extensions, config, {
        tenantId: this.tenantId,
        clientId: this.clientId,
        redirectUri: this.redirectUri,
      });

      // Create CloudFront Function
      const functionId = this.generateFunctionId(extensions, config);

      // Add KVS if auth extension is included
      const functionProps = extensions.includes(Extension.REQUIRE_AUTH)
        ? {
          code: cloudfront.FunctionCode.fromInline(code),
          runtime: cloudfront.FunctionRuntime.JS_2_0,
          comment: `Combined: ${extensions.join(', ')}`,
          keyValueStore: this.kvs,
        }
        : {
          code: cloudfront.FunctionCode.fromInline(code),
          runtime: cloudfront.FunctionRuntime.JS_2_0,
          comment: `Combined: ${extensions.join(', ')}`,
        };

      func = new cloudfront.Function(this, functionId, functionProps);

      if (this.lastCreatedFunction) {
        func.node.addDependency(this.lastCreatedFunction);
      }
      this.lastCreatedFunction = func;

      this.composedFunctions.set(cacheKey, func);
    }

    const result: { functionAssociations: cloudfront.FunctionAssociation[]; originRequestPolicy?: cloudfront.OriginRequestPolicy } = {
      functionAssociations: [{
        function: func,
        eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
      }],
    };

    if (extensions.includes(Extension.REQUIRE_TLS_13)) {
      result.originRequestPolicy = this.tlsOriginRequestPolicy;
    }

    return result;
  }

  private generateFunctionCacheKey(extensions: Extension[], config?: ExtensionConfig<TRole>): string {
    const parts = [extensions.sort().join(',')];
    if (config?.requiredRoles) {
      parts.push([...config.requiredRoles].sort().join(','));
    }
    if (config?.roleMatchMode && config.roleMatchMode !== RoleMatchMode.OR) {
      parts.push(config.roleMatchMode);
    }
    return parts.join('|');
  }

  private generateFunctionId(extensions: Extension[], config?: ExtensionConfig<TRole>): string {
    const extensionPart = extensions.map(e => e.replace('REQUIRE_', '')).join('');
    if (config?.requiredRoles && config.requiredRoles.length > 0) {
      const roleHash = config.requiredRoles.join('').replace(/[^a-zA-Z0-9]/g, '').substring(0, 8);
      const modePart = config.roleMatchMode && config.roleMatchMode !== RoleMatchMode.OR ? config.roleMatchMode : '';
      return `ComposedFunction${extensionPart}${roleHash}${modePart}`;
    }
    return `ComposedFunction${extensionPart}`;
  }

  private determineRedirectUri(redirectUri?: string, domainNames?: string[]): string {
    if (redirectUri) {
      return redirectUri;
    }
    if (!domainNames || domainNames.length === 0) {
      throw new Error('Either redirectUri or domainNames must be provided');
    }
    return `https://${domainNames[0]}/oauth2/callback`;
  }

  private loadAndReplaceAuthCheckCode(tenantId: string, clientId: string, redirectUri: string): string {
    const codePath = path.join(__dirname, '../cloudfront-functions/auth-check.js');
    let code = fs.readFileSync(codePath, 'utf-8');
    code = code.replace('TENANT_ID_PLACEHOLDER', tenantId);
    code = code.replace('CLIENT_ID_PLACEHOLDER', clientId);
    code = code.replace('REDIRECT_URI_PLACEHOLDER', redirectUri);
    return code;
  }

  private loadAndReplaceUserInfoCode(nameFields: string[]): string {
    const codePath = path.join(__dirname, '../cloudfront-functions/userinfo-endpoint.js');
    let code = fs.readFileSync(codePath, 'utf-8');

    // Replace the nameFields array with the provided fields
    const nameFieldsJson = JSON.stringify(nameFields);
    code = code.replace(
      "var nameFields = ['key1', 'key2', 'key3'];",
      `var nameFields = ${nameFieldsJson};`,
    );

    return code;
  }
}
