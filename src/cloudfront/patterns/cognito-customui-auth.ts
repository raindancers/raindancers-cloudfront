import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_certificatemanager as acm,
  aws_cloudfront as cloudfront,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_secretsmanager as secretsmanager,
  aws_ssm as ssm,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';
import { Extension, ExtensionConfig, AddBehaviorOptions, RoleMatchMode } from './securedCloudFront';
import { FunctionComposer } from '../cloudfront-functions/function-composer';

/**
 * Props for {@link CognitoCustomUiAuth}.
 *
 * Configures customer authentication for a storefront CloudFront distribution
 * using AWS Cognito with a first-party (custom) login UI. Unauthenticated
 * requests to protected paths are redirected to {@link unauthenticatedRedirectPath}
 * on the brand's own domain — never to a Cognito hosted UI. The login page
 * performs SRP client-side and POSTs the resulting tokens to the session-issuance
 * endpoint; Cognito tokens are never stored in the browser.
 *
 * The backend (user pool, HMAC key, auth table, KVS, config secret) is provided
 * by {@link CognitoAuthInfrastructure} and referenced here via SSM parameters
 * written under {@link authSsmParamPrefix}.
 */
export interface CognitoCustomUiAuthProps<TRole extends string = string> {
  /**
   * CREATE MODE: default cache behaviour for a distribution this construct will
   * create. Provide with {@link certificate}. Mutually exclusive with
   * {@link distribution}. You MAY set `functionAssociations` here (e.g. a
   * geo-routing viewer-request function) — it is merged with the auth-check
   * function; CloudFront's one-function-per-event-type rule is enforced with a
   * clear error rather than an L1 override.
   */
  readonly defaultBehavior?: cloudfront.BehaviorOptions;
  /** Domain names for the auth config (allowed_domains); first is canonical. Required in both modes. */
  readonly domainNames: string[];
  /**
   * Name of the shared session config secret the edge Lambdas fetch by name.
   * MUST match the name the {@link CognitoSessionBackend} created it under.
   * Override to decouple from the canonical domain.
   * @default `cloudfront-auth-config-${domainNames[0]}`
   */
  readonly configSecretName?: string;
  /** CREATE MODE: ACM certificate (us-east-1) covering {@link domainNames}. */
  readonly certificate?: acm.ICertificate;
  /** CREATE MODE: WAF web ACL ARN to associate with the created distribution. */
  readonly webAclId?: string;
  /**
   * ATTACH MODE: an existing distribution to add the auth endpoint + protected
   * behaviours to, instead of creating one. Mutually exclusive with
   * {@link defaultBehavior}/{@link certificate}. CloudFront allows only one
   * function per event type per behaviour, so the auth-check is added to protected
   * PATH behaviours (via {@link protect}) — it is NOT forced onto the existing
   * default behaviour. Use {@link authFunction} to compose it there yourself.
   */
  readonly distribution?: cloudfront.Distribution;
  /**
   * Origin for the auth endpoint behaviours (issuance / refresh / logout). These
   * endpoints are generated entirely by Lambda@Edge and never reach the origin,
   * but a CloudFront behaviour still requires one.
   *
   * Defaults to the {@link defaultBehavior} origin. Set this to a NON-VPC origin
   * (for example an S3 origin already on the distribution) when the default
   * behaviour's origin is a CloudFront VPC origin: AWS does not allow an
   * origin-request Lambda@Edge association on a VPC-origin behaviour, and these
   * endpoints run at origin-request. REQUIRED in ATTACH MODE (when
   * {@link distribution} is set).
   */
  readonly authEndpointOrigin?: cloudfront.IOrigin;
  /**
   * SSM parameter prefix under which {@link CognitoAuthInfrastructure} published
   * `configSecretArn`, `kmsKeyArn`, `authTableArn`, `kvsArn`, `cognitoDomain`,
   * `clientId` and `userPoolId`.
   */
  readonly authSsmParamPrefix: string;
  /** Region the auth backend (config secret, auth table) lives in. */
  readonly authRegion: string;
  /** First-party path unauthenticated users are redirected to. @default '/login' */
  readonly unauthenticatedRedirectPath?: string;
  /** Extensions applied to the default behaviour. @default [] (public) */
  readonly defaultExtensions?: Extension[];
  /** Role configuration for the default behaviour. */
  readonly defaultExtensionConfig?: ExtensionConfig<TRole>;
  /** Inject validated identity claims as origin headers. @default true */
  readonly enableHeaderInjection?: boolean;
  /**
   * Map of origin header name to session-JWT claim key.
   * @default { 'x-customer-id': 'customer_id', 'x-customer-email': 'email' }
   */
  readonly headerInjectionClaims?: Record<string, string>;
  /** Path of the session-issuance endpoint (POST). @default '/auth/session' */
  readonly sessionIssuancePath?: string;
  /** Mount the silent-refresh endpoint at '/oauth2/refresh'. @default true */
  readonly enableRefreshEndpoint?: boolean;
  /** Mount the logout endpoint at '/oauth2/logout' (POST). @default true */
  readonly enableLogoutEndpoint?: boolean;
  /** URL of the identity-linking hook the issuance endpoint calls to resolve customer_id. */
  readonly identityLinkingHookUrl: string;
  /** Secrets Manager ARN of the shared secret used to authenticate to the hook. */
  readonly identityLinkingHookSecretArn?: string;
  /** Session JWT lifetime, seconds. @default 3600 */
  readonly sessionTtlSeconds?: number;
  /** Stored refresh-token lifetime, days. @default 30 */
  readonly refreshTtlDays?: number;
  /** Path to redirect to after logout. @default '/' */
  readonly postLogoutRedirectPath?: string;
  /** Add SPA custom error responses. @default false */
  readonly enableErrorResponses?: boolean;
  /** Error page path when {@link enableErrorResponses} is set. @default '/error.html' */
  readonly errorResponsePagePath?: string;
  /** Default root object. @default 'index.html' */
  readonly defaultRootObject?: string;
  /**
   * CREATE MODE: minimum TLS security policy for the created distribution's
   * viewer connections. Defaults to the current-generation policy; override only
   * to relax it (not recommended). Ignored in ATTACH MODE — the passed-in
   * distribution already fixes its own policy.
   * @default cloudfront.SecurityPolicyProtocol.TLS_V1_2_2025
   */
  readonly minimumProtocolVersion?: cloudfront.SecurityPolicyProtocol;
  /**
   * Allowed viewer HTTP methods for the auth endpoint behaviours (session
   * issuance, refresh, logout). These endpoints are POST-driven, so the default
   * permits all methods; CloudFront's GET/HEAD default would otherwise reject the
   * POST they require. Override to narrow it (must still include POST).
   * @default cloudfront.AllowedMethods.ALLOW_ALL
   */
  readonly authEndpointAllowedMethods?: cloudfront.AllowedMethods;
}

/**
 * Customer authentication for a storefront CloudFront distribution using Cognito
 * with a custom, brand-domain login UI.
 *
 * OWNS (in this library): the edge session-validation function (reused shared
 * module, redirecting to a first-party /login), the session-issuance / refresh /
 * logout Lambda@Edge functions, and their IAM wiring. CONSUMES: the Cognito
 * backend from {@link CognitoAuthInfrastructure}. Does NOT provision the user
 * pool — that is the backend construct's job.
 */
export class CognitoCustomUiAuth<TRole extends string = string> extends constructs.Construct {
  public readonly distribution: cloudfront.Distribution;

  private readonly composer: FunctionComposer;
  private readonly composedFunctions: Map<string, cloudfront.Function>;
  private readonly kvs: cloudfront.IKeyValueStore;
  private readonly loginRedirectPath: string;
  private readonly enableHeaderInjection: boolean;
  private readonly headerInjectionClaims: Record<string, string>;
  private readonly enableRefresh: boolean;
  private lastCreatedFunction: cloudfront.Function | undefined;

  constructor(scope: constructs.Construct, id: string, props: CognitoCustomUiAuthProps<TRole>) {
    super(scope, id);

    const attachMode = props.distribution !== undefined;
    if (attachMode && !props.authEndpointOrigin) {
      throw new Error('authEndpointOrigin is required when attaching to an existing distribution');
    }
    if (!attachMode && (!props.defaultBehavior || !props.certificate)) {
      throw new Error('defaultBehavior and certificate are required when creating a distribution');
    }

    const p = props.authSsmParamPrefix;
    const configSecretArn = ssm.StringParameter.valueForStringParameter(this, `${p}/configSecretArn`);
    const kmsKeyArn = ssm.StringParameter.valueForStringParameter(this, `${p}/kmsKeyArn`);
    const authTableArn = ssm.StringParameter.valueForStringParameter(this, `${p}/authTableArn`);
    const kvsArn = ssm.StringParameter.valueForStringParameter(this, `${p}/kvsArn`);

    this.kvs = cloudfront.KeyValueStore.fromKeyValueStoreArn(this, 'KVS', kvsArn);
    this.loginRedirectPath = props.unauthenticatedRedirectPath ?? '/login';
    this.enableHeaderInjection = props.enableHeaderInjection ?? true;
    this.headerInjectionClaims = props.headerInjectionClaims ?? {
      'x-customer-id': 'customer_id',
      'x-customer-email': 'email',
    };
    this.enableRefresh = props.enableRefreshEndpoint ?? true;
    this.composer = new FunctionComposer();
    this.composedFunctions = new Map();

    const canonicalDomain = props.domainNames[0];
    const baseSecretName = props.configSecretName ?? `cloudfront-auth-config-${canonicalDomain}`;
    const sessionIssuancePath = props.sessionIssuancePath ?? '/auth/session';

    // Extra config secret for values that are CDK tokens at synth time (and so
    // cannot be baked into config_generated.py) — Lambda@Edge forbids env vars.
    // Bake the LITERAL name below, NOT `extraConfigSecret.secretName`: that
    // property is a deploy-time token (CloudFormation derives it by parsing the
    // secret ARN), so baking it into config_generated.py at synth renders it as
    // `${Token[Fn::Join.NNNN]}`. The edge's `get_secret_value(SecretId=...)`
    // then fails with `ValidationException: Invalid name`, the extra config
    // (post_auth_hook_url, kvs_arn, post_auth_hook_secret_arn) never loads, and
    // the identity-linking hook is silently never called.
    const extraConfigSecretName = `cloudfront-customui-config-${canonicalDomain}`;
    const extraConfigSecret = new secretsmanager.Secret(this, 'CustomUiConfigSecret', {
      secretName: extraConfigSecretName,
      secretObjectValue: {
        kvs_arn: core.SecretValue.unsafePlainText(kvsArn),
        post_auth_hook_url: core.SecretValue.unsafePlainText(props.identityLinkingHookUrl),
        post_auth_hook_secret_arn: core.SecretValue.unsafePlainText(props.identityLinkingHookSecretArn ?? ''),
      },
      description: `Custom-UI auth config overrides for ${canonicalDomain}`,
    });

    const staticOverrides: Record<string, string> = {
      login_redirect_path: this.loginRedirectPath,
      allowed_domains: JSON.stringify(props.domainNames),
      session_ttl_seconds: String(props.sessionTtlSeconds ?? 3600),
      refresh_ttl_days: String(props.refreshTtlDays ?? 30),
      post_logout_redirect_path: props.postLogoutRedirectPath ?? '/',
      config_region: props.authRegion,
    };

    // The base config secret lives in authRegion, but extraConfigSecret is created
    // in THIS construct's own stack (us-east-1 for the CloudFront edge stack). The
    // edge must look each secret up in its own region, so pass both regions through.
    const extraSecretRegion = core.Stack.of(this).region;
    const configPy = this.renderConfigPy(baseSecretName, extraConfigSecretName, props.authRegion, extraSecretRegion, staticOverrides);

    // Shared IAM grants factory for the edge Lambdas.
    const grantCommon = (role: iam.IRole, opts: { kms: boolean; ddb: boolean; kvs: boolean; cognito: boolean; hookSecret: boolean }): void => {
      role.addToPrincipalPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resources: [configSecretArn, extraConfigSecret.secretArn],
      }));
      if (opts.hookSecret && props.identityLinkingHookSecretArn) {
        role.addToPrincipalPolicy(new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['secretsmanager:GetSecretValue'],
          resources: [props.identityLinkingHookSecretArn],
        }));
      }
      if (opts.kms) {
        role.addToPrincipalPolicy(new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['kms:Decrypt'],
          resources: [kmsKeyArn],
        }));
      }
      if (opts.ddb) {
        role.addToPrincipalPolicy(new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:DeleteItem', 'dynamodb:Query'],
          resources: [authTableArn, `${authTableArn}/index/*`],
        }));
      }
      if (opts.kvs) {
        role.addToPrincipalPolicy(new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['cloudfront-keyvaluestore:PutKey', 'cloudfront-keyvaluestore:DescribeKeyValueStore'],
          resources: [kvsArn],
        }));
      }
      if (opts.cognito) {
        role.addToPrincipalPolicy(new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['cognito-idp:InitiateAuth', 'cognito-idp:RevokeToken'],
          resources: ['*'],
        }));
      }
    };

    const edgeRole = (roleId: string): iam.Role => new iam.Role(this, roleId, {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // Session-issuance Lambda: verifies the Cognito id_token with the pure-Python
    // `rsa` library, bundled from its own cognito-customui-session deps dir (NOT the
    // fat PyJWT/cryptography cognito-auth bundle) so it fits the 1 MB viewer-request
    // Lambda@Edge code limit.
    const issuanceRole = edgeRole('IssuanceRole');
    grantCommon(issuanceRole, { kms: true, ddb: true, kvs: false, cognito: false, hookSecret: true });
    const issuanceFn = this.makeEdgeFunction('SessionIssuance', 'cognito-customui-session', configPy, issuanceRole, 'cognito-customui-session');

    // Refresh + logout Lambdas (boto3 only — no bundled deps).
    let refreshFn: cloudfront.experimental.EdgeFunction | undefined;
    if (this.enableRefresh) {
      const refreshRole = edgeRole('RefreshRole');
      grantCommon(refreshRole, { kms: true, ddb: true, kvs: false, cognito: true, hookSecret: false });
      refreshFn = this.makeEdgeFunction('SessionRefresh', 'cognito-customui-refresh', configPy, refreshRole);
    }

    let logoutFn: cloudfront.experimental.EdgeFunction | undefined;
    if (props.enableLogoutEndpoint ?? true) {
      const logoutRole = edgeRole('LogoutRole');
      grantCommon(logoutRole, { kms: true, ddb: true, kvs: true, cognito: true, hookSecret: false });
      logoutFn = this.makeEdgeFunction('SessionLogout', 'cognito-customui-logout', configPy, logoutRole);
    }

    // Retain old Lambda@Edge versions on a real update/delete — edge replicas
    // take hours to drain — but let CloudFormation delete a version whose
    // CREATE was rolled back (RetainExceptOnCreate). A plain RETAIN orphans the
    // version (and, through it, the function and its IAM role) on a failed
    // create, blocking the next deploy's import; RETAIN_ON_UPDATE_OR_DELETE
    // keeps the drain-safe retain behaviour without the orphan.
    for (const fn of [issuanceFn, refreshFn, logoutFn]) {
      if (!fn) continue;
      const version = fn.currentVersion.node.defaultChild as core.CfnResource;
      if (version) {
        version.applyRemovalPolicy(core.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE);
      }
    }

    // Endpoint behaviours use authEndpointOrigin when supplied (a non-VPC origin,
    // required when the default behaviour's origin is a VPC origin), else the
    // default behaviour's origin. Attach mode guarantees authEndpointOrigin is set.
    const endpointOrigin: cloudfront.IOrigin = props.authEndpointOrigin ?? props.defaultBehavior!.origin;

    // Auth endpoints are POST-driven; CloudFront otherwise defaults to GET/HEAD
    // and rejects the POST these endpoints require. Allow all methods by default.
    const authEndpointAllowedMethods = props.authEndpointAllowedMethods ?? cloudfront.AllowedMethods.ALLOW_ALL;

    const endpointOpts = (fn: cloudfront.experimental.EdgeFunction, includeBody: boolean): cloudfront.AddBehaviorOptions => ({
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      allowedMethods: authEndpointAllowedMethods,
      // Set-Cookie must reach the viewer — caching disabled.
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      edgeLambdas: [{
        functionVersion: fn.currentVersion,
        // Viewer-request: these functions generate the response entirely at the
        // edge and never contact the origin. Viewer-request fires reliably on a
        // cache miss regardless of origin type (unlike origin-request, which is
        // illegal on a VPC-origin behaviour and — as observed on attach-mode
        // distributions — could silently fail to intercept, letting the request
        // fall through to the placeholder origin). It caps code at 1 MB, which
        // the session-issuance function now fits after dropping PyJWT/cryptography
        // for the pure-Python `rsa` library. The behaviour still needs a target
        // origin (endpointOrigin), but it is a never-contacted placeholder.
        eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
        includeBody: includeBody,
      }],
    });

    if (attachMode) {
      this.distribution = props.distribution!;
      this.distribution.addBehavior(sessionIssuancePath, endpointOrigin, endpointOpts(issuanceFn, true));
      if (refreshFn) {
        this.distribution.addBehavior('/oauth2/refresh', endpointOrigin, endpointOpts(refreshFn, false));
      }
      if (logoutFn) {
        this.distribution.addBehavior('/oauth2/logout', endpointOrigin, endpointOpts(logoutFn, true));
      }
    } else {
      const additionalBehaviors: Record<string, cloudfront.BehaviorOptions> = {
        [sessionIssuancePath]: { origin: endpointOrigin, ...endpointOpts(issuanceFn, true) },
      };
      if (refreshFn) {
        additionalBehaviors['/oauth2/refresh'] = { origin: endpointOrigin, ...endpointOpts(refreshFn, false) };
      }
      if (logoutFn) {
        additionalBehaviors['/oauth2/logout'] = { origin: endpointOrigin, ...endpointOpts(logoutFn, true) };
      }

      this.distribution = new cloudfront.Distribution(this, 'Distribution', {
        httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
        minimumProtocolVersion: props.minimumProtocolVersion ?? cloudfront.SecurityPolicyProtocol.TLS_V1_2_2025,
        defaultBehavior: {
          ...props.defaultBehavior!,
          functionAssociations: this.mergeFunctionAssociations(
            this.buildFunctionAssociations(props.defaultExtensions, props.defaultExtensionConfig),
            props.defaultBehavior!.functionAssociations,
          ),
        },
        additionalBehaviors: additionalBehaviors,
        domainNames: props.domainNames,
        certificate: props.certificate!,
        webAclId: props.webAclId,
        defaultRootObject: props.defaultRootObject ?? 'index.html',
        errorResponses: props.enableErrorResponses ? [
          { httpStatus: 403, responseHttpStatus: 200, responsePagePath: props.errorResponsePagePath ?? '/error.html', ttl: core.Duration.minutes(5) },
          { httpStatus: 404, responseHttpStatus: 200, responsePagePath: props.errorResponsePagePath ?? '/error.html', ttl: core.Duration.minutes(5) },
        ] : [],
      });
    }
  }

  /**
   * Add a behaviour. Pass `options.extensions = [Extension.REQUIRE_AUTH]` to
   * protect the path (unauthenticated requests redirect to the login page and
   * validated identity claims are injected as origin headers).
   */
  public addBehavior(
    pathPattern: string,
    origin: cloudfront.IOrigin,
    options: AddBehaviorOptions<TRole> = {},
  ): void {
    this.distribution.addBehavior(pathPattern, origin, {
      ...options.behaviorOptions,
      functionAssociations: this.mergeFunctionAssociations(
        this.buildFunctionAssociations(options.extensions, options.extensionConfig),
        options.behaviorOptions?.functionAssociations,
      ),
    });
  }

  /**
   * Merge two sets of function associations, enforcing CloudFront's rule of one
   * function per event type per behaviour. The library never composes or inspects
   * a consumer's function — it only attaches it; combining two functions on the
   * same event type is the consumer's responsibility (a single function).
   */
  private mergeFunctionAssociations(
    auth?: cloudfront.FunctionAssociation[],
    consumer?: cloudfront.FunctionAssociation[],
  ): cloudfront.FunctionAssociation[] | undefined {
    const all = [...(auth ?? []), ...(consumer ?? [])];
    if (all.length === 0) {
      return undefined;
    }
    const seen = new Set<cloudfront.FunctionEventType>();
    for (const fa of all) {
      if (seen.has(fa.eventType)) {
        throw new Error(
          `CloudFront allows only one function per event type per behaviour, but two '${fa.eventType}' ` +
          'functions were supplied (e.g. REQUIRE_AUTH plus your own function). Keep auth and your other ' +
          'function on separate path behaviours, or combine them into a single function yourself.',
        );
      }
      seen.add(fa.eventType);
    }
    return all;
  }

  /**
   * Add a PROTECTED behaviour: unauthenticated requests redirect to the login
   * page and validated identity claims are injected as origin headers.
   * Convenience wrapper over {@link addBehavior} that ensures REQUIRE_AUTH.
   */
  public protect(
    pathPattern: string,
    origin: cloudfront.IOrigin,
    options: AddBehaviorOptions<TRole> = {},
  ): void {
    const extensions = options.extensions ? [...options.extensions] : [];
    if (!extensions.includes(Extension.REQUIRE_AUTH)) {
      extensions.push(Extension.REQUIRE_AUTH);
    }
    this.addBehavior(pathPattern, origin, { ...options, extensions: extensions });
  }

  /**
   * The composed viewer-request auth-check function (REQUIRE_AUTH). Useful in
   * ATTACH MODE to associate or compose auth onto a behaviour this construct does
   * not own — e.g. an existing default behaviour, via an L1 override.
   */
  public get authFunction(): cloudfront.Function {
    return this.composedAuthFunction([Extension.REQUIRE_AUTH]);
  }

  private buildFunctionAssociations(
    extensions?: Extension[],
    config?: ExtensionConfig<TRole>,
  ): cloudfront.FunctionAssociation[] | undefined {
    if (!extensions || extensions.length === 0) {
      return undefined;
    }
    return [{ function: this.composedAuthFunction(extensions, config), eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }];
  }

  private composedAuthFunction(
    extensions: Extension[],
    config?: ExtensionConfig<TRole>,
  ): cloudfront.Function {
    const cacheKey = this.functionCacheKey(extensions, config);
    let func = this.composedFunctions.get(cacheKey);
    if (!func) {
      const code = this.composer.compose(extensions, config, {
        loginRedirectPath: this.loginRedirectPath,
        enableHeaderInjection: this.enableHeaderInjection,
        headerInjectionClaims: this.headerInjectionClaims,
        enableRefresh: this.enableRefresh,
      });
      const functionId = `ComposedFn${extensions.map(e => e.replace('REQUIRE_', '')).join('')}${this.composedFunctions.size}`;
      const needsKvs = extensions.includes(Extension.REQUIRE_AUTH);
      func = new cloudfront.Function(this, functionId, needsKvs
        ? { code: cloudfront.FunctionCode.fromInline(code), runtime: cloudfront.FunctionRuntime.JS_2_0, comment: `Custom-UI: ${extensions.join(', ')}`, keyValueStore: this.kvs }
        : { code: cloudfront.FunctionCode.fromInline(code), runtime: cloudfront.FunctionRuntime.JS_2_0, comment: `Custom-UI: ${extensions.join(', ')}` });
      if (this.lastCreatedFunction) {
        func.node.addDependency(this.lastCreatedFunction);
      }
      this.lastCreatedFunction = func;
      this.composedFunctions.set(cacheKey, func);
    }
    return func;
  }

  private functionCacheKey(extensions: Extension[], config?: ExtensionConfig<TRole>): string {
    const parts = [extensions.slice().sort().join(',')];
    if (config?.requiredRoles) {
      parts.push(config.requiredRoles.slice().sort().join(','));
    }
    if (config?.roleMatchMode && config.roleMatchMode !== RoleMatchMode.OR) {
      parts.push(config.roleMatchMode);
    }
    return parts.join('|');
  }

  private renderConfigPy(
    baseSecretName: string,
    extraSecretName: string,
    region: string,
    extraSecretRegion: string,
    staticOverrides: Record<string, string>,
  ): string {
    return [
      'import json',
      'import logging',
      'import boto3',
      '',
      'logger = logging.getLogger()',
      `BASE_SECRET_NAME = ${JSON.stringify(baseSecretName)}`,
      `EXTRA_SECRET_NAME = ${JSON.stringify(extraSecretName)}`,
      `CONFIG_REGION = ${JSON.stringify(region)}`,
      `EXTRA_SECRET_REGION = ${JSON.stringify(extraSecretRegion)}`,
      `STATIC_OVERRIDES = ${JSON.stringify(staticOverrides)}`,
      '',
      '_sm = None',
      '_sm_extra = None',
      '',
      '',
      'def _client():',
      '    global _sm',
      '    if _sm is None:',
      '        _sm = boto3.client("secretsmanager", region_name=CONFIG_REGION)',
      '    return _sm',
      '',
      '',
      'def _extra_client():',
      '    # The extra-config secret lives in EXTRA_SECRET_REGION (the edge stack region),',
      '    # which differs from CONFIG_REGION (the base secret in authRegion). Reuse the',
      '    # base client when the two happen to match, otherwise build a region-specific one.',
      '    global _sm_extra',
      '    if EXTRA_SECRET_REGION == CONFIG_REGION:',
      '        return _client()',
      '    if _sm_extra is None:',
      '        _sm_extra = boto3.client("secretsmanager", region_name=EXTRA_SECRET_REGION)',
      '    return _sm_extra',
      '',
      '',
      'def get_config():',
      '    cfg = json.loads(_client().get_secret_value(SecretId=BASE_SECRET_NAME)["SecretString"])',
      '    try:',
      '        cfg.update(json.loads(_extra_client().get_secret_value(SecretId=EXTRA_SECRET_NAME)["SecretString"]))',
      '    except Exception as e:',
      '        logger.error("extra config load failed: %s", e)',
      '    cfg.update(STATIC_OVERRIDES)',
      '    return cfg',
      '',
    ].join('\n');
  }

  private makeEdgeFunction(
    id: string,
    sourceDirName: string,
    configPy: string,
    role: iam.IRole,
    bundledDepsName?: string,
  ): cloudfront.experimental.EdgeFunction {
    const sourceDir = path.join(__dirname, '../lambda', sourceDirName);
    const bundledDepsDir = bundledDepsName ? path.join(__dirname, '../lambda-bundled', bundledDepsName) : undefined;
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'customui-auth-'));
    const configPyPath = path.join(tempDir, 'config_generated.py');
    fs.writeFileSync(configPyPath, configPy);

    return new cloudfront.experimental.EdgeFunction(this, id, {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'index.lambda_handler',
      timeout: core.Duration.seconds(30),
      memorySize: 128,
      role: role,
      code: lambda.Code.fromAsset(sourceDir, {
        bundling: {
          local: {
            tryBundle(outputDir: string): boolean {
              if (bundledDepsDir && fs.existsSync(bundledDepsDir)) {
                fs.cpSync(bundledDepsDir, outputDir, { recursive: true });
              }
              for (const file of fs.readdirSync(sourceDir)) {
                if (file === 'requirements.txt') continue;
                fs.cpSync(path.join(sourceDir, file), path.join(outputDir, file), { recursive: true });
              }
              fs.writeFileSync(path.join(outputDir, 'config_generated.py'), configPy);
              return true;
            },
          },
          image: lambda.Runtime.PYTHON_3_11.bundlingImage,
          command: [
            'bash', '-c',
            'pip install -r requirements.txt -t /asset-output && cp -r . /asset-output && cp /tmp/config_generated.py /asset-output/config_generated.py',
          ],
          volumes: [{ hostPath: configPyPath, containerPath: '/tmp/config_generated.py' }],
        },
      }),
    });
  }
}
