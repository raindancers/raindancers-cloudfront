import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_ssm as ssm,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';
import { Extension, ExtensionConfig, AddBehaviorOptions, RoleMatchMode } from './securedCloudFront';
import { FunctionComposer } from '../cloudfront-functions/function-composer';

export interface CognitoCloudFrontProps<TRole extends string = string> {
  readonly defaultBehavior: Omit<cloudfront.BehaviorOptions, 'functionAssociations'>;
  readonly domainNames: string[];
  readonly certificate: any;
  readonly authSsmParamPrefix: string;
  readonly authRegion: string;
  readonly defaultExtensions?: Extension[];
  readonly defaultExtensionConfig?: ExtensionConfig<TRole>;
  readonly defaultRootObject?: string;
  readonly errorResponsePagePath?: string;
  /** Whether to add custom error responses (SPA routing). Defaults to true. */
  readonly enableErrorResponses?: boolean;
  readonly enableUserInfoInjection?: boolean;
  readonly userInfoNameFields?: string[];
}

export class CognitoSecuredCloudFront<TRole extends string = string> extends constructs.Construct {
  public readonly distribution: cloudfront.Distribution;
  private readonly authCheckFunction: cloudfront.Function;
  private readonly userInfoFunction?: cloudfront.Function;
  private readonly functionComposer: FunctionComposer;
  private readonly composedFunctions: Map<string, cloudfront.Function>;
  private lastCreatedFunction: cloudfront.Function | undefined;
  private readonly tlsOriginRequestPolicy: cloudfront.OriginRequestPolicy;
  private readonly cognitoDomain: string;
  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly kvs: cloudfront.IKeyValueStore;

  constructor(scope: constructs.Construct, id: string, props: CognitoCloudFrontProps<TRole>) {
    super(scope, id);

    const redirectUri = `https://${props.domainNames[0]}/oauth2/callback`;

    const p = props.authSsmParamPrefix;
    const configSecretArn = ssm.StringParameter.valueForStringParameter(this, `${p}/configSecretArn`);
    const kmsKeyArn = ssm.StringParameter.valueForStringParameter(this, `${p}/kmsKeyArn`);
    const authTableArn = ssm.StringParameter.valueForStringParameter(this, `${p}/authTableArn`);
    const kvsArn = ssm.StringParameter.valueForStringParameter(this, `${p}/kvsArn`);
    const cognitoDomain = ssm.StringParameter.valueForStringParameter(this, `${p}/cognitoDomain`);
    const clientId = ssm.StringParameter.valueForStringParameter(this, `${p}/clientId`);

    this.cognitoDomain = cognitoDomain;
    this.clientId = clientId;
    this.redirectUri = redirectUri;

    const kvs = cloudfront.KeyValueStore.fromKeyValueStoreArn(this, 'KVS', kvsArn);
    this.kvs = kvs;

    const lambdaEdgeRole = new iam.Role(this, 'LambdaEdgeRole', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    lambdaEdgeRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
      resources: [configSecretArn],
    }));

    lambdaEdgeRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['kms:Decrypt'],
      resources: [kmsKeyArn],
    }));

    lambdaEdgeRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query', 'dynamodb:Scan', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem'],
      resources: [authTableArn],
    }));

    const configPyContent = `# Generated configuration
import json
import boto3
import logging

logger = logging.getLogger()

CONFIG_SECRET_NAME = 'cloudfront-auth-config-${props.domainNames[0]}'
CONFIG_REGION = '${props.authRegion}'

def get_config():
    logger.info(f'Loading config from Secrets Manager')
    try:
        client = boto3.client('secretsmanager', region_name=CONFIG_REGION)
        response = client.get_secret_value(SecretId=CONFIG_SECRET_NAME)
        return json.loads(response['SecretString'])
    except Exception as e:
        logger.error(f'Failed to get secret: {str(e)}')
        raise
`;

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cognito-auth-'));
    const configPyPath = path.join(tempDir, 'config_generated.py');
    fs.writeFileSync(configPyPath, configPyContent);

    const oauthCallbackFn = new cloudfront.experimental.EdgeFunction(this, 'OAuthCallback', {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'oauth-callback.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/cognito-auth'), {
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
      role: lambdaEdgeRole,
    });

    const authCheckCode = this.buildAuthCheckCode(cognitoDomain, clientId, redirectUri);

    this.authCheckFunction = new cloudfront.Function(this, 'AuthCheck', {
      code: cloudfront.FunctionCode.fromInline(authCheckCode),
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      keyValueStore: kvs,
      comment: 'Cognito auth check',
    });
    this.lastCreatedFunction = this.authCheckFunction;

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

    this.tlsOriginRequestPolicy = new cloudfront.OriginRequestPolicy(this, 'TlsOriginRequestPolicy', {
      headerBehavior: cloudfront.OriginRequestHeaderBehavior.allowList('CloudFront-Viewer-TLS'),
      cookieBehavior: cloudfront.OriginRequestCookieBehavior.none(),
      queryStringBehavior: cloudfront.OriginRequestQueryStringBehavior.none(),
    });

    this.functionComposer = new FunctionComposer();
    this.composedFunctions = new Map();

    const oauthCallbackBehavior: cloudfront.BehaviorOptions = {
      origin: props.defaultBehavior.origin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      edgeLambdas: [{
        functionVersion: oauthCallbackFn.currentVersion,
        eventType: cloudfront.LambdaEdgeEventType.ORIGIN_REQUEST,
      }],
      cachePolicy: new cloudfront.CachePolicy(this, 'CallbackCachePolicy', {
        cachePolicyName: `${core.Stack.of(this).stackName}-cognito-callback`,
        defaultTtl: core.Duration.seconds(0),
        minTtl: core.Duration.seconds(0),
        maxTtl: core.Duration.seconds(1),
        cookieBehavior: cloudfront.CacheCookieBehavior.allowList('oauth_state', 'code_verifier'),
        headerBehavior: cloudfront.CacheHeaderBehavior.none(),
        queryStringBehavior: cloudfront.CacheQueryStringBehavior.all(),
        enableAcceptEncodingGzip: false,
        enableAcceptEncodingBrotli: false,
      }),
    };

    this.distribution = new cloudfront.Distribution(this, 'Distribution', {
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2025,
      defaultBehavior: (() => {
        const built = this.buildFunctionAssociations(props.defaultExtensions, props.defaultExtensionConfig);
        return {
          ...props.defaultBehavior,
          functionAssociations: built?.functionAssociations,
          originRequestPolicy: built?.originRequestPolicy,
        };
      })(),
      additionalBehaviors: {
        '/oauth2/callback': oauthCallbackBehavior,
      },
      domainNames: props.domainNames,
      certificate: props.certificate,
      defaultRootObject: props.defaultRootObject ?? 'index.html',
      errorResponses: (props.enableErrorResponses ?? true) ? [
        { httpStatus: 403, responseHttpStatus: 200, responsePagePath: props.errorResponsePagePath ?? '/error.html', ttl: core.Duration.minutes(5) },
        { httpStatus: 404, responseHttpStatus: 200, responsePagePath: props.errorResponsePagePath ?? '/error.html', ttl: core.Duration.minutes(5) },
        { httpStatus: 500, responseHttpStatus: 200, responsePagePath: props.errorResponsePagePath ?? '/error.html', ttl: core.Duration.seconds(10) },
        { httpStatus: 502, responseHttpStatus: 200, responsePagePath: props.errorResponsePagePath ?? '/error.html', ttl: core.Duration.seconds(10) },
        { httpStatus: 503, responseHttpStatus: 200, responsePagePath: props.errorResponsePagePath ?? '/error.html', ttl: core.Duration.seconds(10) },
        { httpStatus: 504, responseHttpStatus: 200, responsePagePath: props.errorResponsePagePath ?? '/error.html', ttl: core.Duration.seconds(10) },
      ] : [],
    });

    if (this.userInfoFunction) {
      this.distribution.addBehavior('/userinfo', props.defaultBehavior.origin, {
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        functionAssociations: [{ function: this.userInfoFunction, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }],
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      });
    }
  }

  public addBehavior(
    pathPattern: string,
    origin: cloudfront.IOrigin,
    options: AddBehaviorOptions<TRole> = {},
  ): void {
    const built = this.buildFunctionAssociations(options.extensions, options.extensionConfig);
    this.distribution.addBehavior(pathPattern, origin, {
      ...options.behaviorOptions,
      functionAssociations: built?.functionAssociations ?? options.behaviorOptions?.functionAssociations,
      originRequestPolicy: built?.originRequestPolicy ?? options.behaviorOptions?.originRequestPolicy,
    });
  }

  private buildFunctionAssociations(
    extensions?: Extension[],
    config?: ExtensionConfig<TRole>,
  ): { functionAssociations: cloudfront.FunctionAssociation[]; originRequestPolicy?: cloudfront.OriginRequestPolicy } | undefined {
    if (!extensions || extensions.length === 0) {
      return undefined;
    }

    const cacheKey = this.generateFunctionCacheKey(extensions, config);
    let func = this.composedFunctions.get(cacheKey);

    if (!func) {
      const code = this.functionComposer.compose(extensions, config, {
        cognitoDomain: this.cognitoDomain,
        clientId: this.clientId,
        redirectUri: this.redirectUri,
      });

      const functionId = this.generateFunctionId(extensions, config);
      const functionProps = extensions.includes(Extension.REQUIRE_AUTH)
        ? { code: cloudfront.FunctionCode.fromInline(code), runtime: cloudfront.FunctionRuntime.JS_2_0, comment: `Combined: ${extensions.join(', ')}`, keyValueStore: this.kvs }
        : { code: cloudfront.FunctionCode.fromInline(code), runtime: cloudfront.FunctionRuntime.JS_2_0, comment: `Combined: ${extensions.join(', ')}` };

      func = new cloudfront.Function(this, functionId, functionProps);
      if (this.lastCreatedFunction) {
        func.node.addDependency(this.lastCreatedFunction);
      }
      this.lastCreatedFunction = func;
      this.composedFunctions.set(cacheKey, func);
    }

    const result: { functionAssociations: cloudfront.FunctionAssociation[]; originRequestPolicy?: cloudfront.OriginRequestPolicy } = {
      functionAssociations: [{ function: func, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }],
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

  private buildAuthCheckCode(cognitoDomain: string, clientId: string, redirectUri: string): string {
    const codePath = path.join(__dirname, '../cloudfront-functions/modules/cognito-auth-check.js');
    let code = fs.readFileSync(codePath, 'utf-8');
    code = code.replace(/COGNITO_DOMAIN_PLACEHOLDER/g, cognitoDomain);
    code = code.replace(/CLIENT_ID_PLACEHOLDER/g, clientId);
    code = code.replace(/REDIRECT_URI_PLACEHOLDER/g, redirectUri);
    return code;
  }

  private loadAndReplaceUserInfoCode(nameFields: string[]): string {
    const codePath = path.join(__dirname, '../cloudfront-functions/userinfo-endpoint.js');
    let code = fs.readFileSync(codePath, 'utf-8');
    code = code.replace(
      "var nameFields = ['key1', 'key2', 'key3'];",
      `var nameFields = ${JSON.stringify(nameFields)};`,
    );
    return code;
  }
}
