import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_apigatewayv2 as apigwv2,
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_dynamodb as dynamodb,
  aws_lambda as lambda,
  aws_logs as logs,
  aws_s3 as s3,
  aws_s3_deployment as s3deploy,
} from 'aws-cdk-lib';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as constructs from 'constructs';

/**
 * An atomic permission in the consumer's catalogue: a stable id and a
 * human-readable name. No consumer domain term appears here — the id is opaque
 * to the construct.
 */
export interface PermissionCatalogueEntry {
  readonly id: string;
  readonly name: string;
}

/** The injected permission catalogue (R8.1). */
export interface PermissionCatalogue {
  readonly permissions: PermissionCatalogueEntry[];
}

/**
 * An injected predefined role: a named subset of the catalogue. Predefined
 * roles are immutable through this surface (R11.3) and occupy the predefined
 * 16-bit mask (R13.1).
 */
export interface PredefinedRole {
  readonly id: string;
  readonly name: string;
  readonly permissionIds: string[];
  /** Fixed bit 0-15 in the predefined mask for this role's scope. */
  readonly bit: number;
}

/** Where the live scope list comes from (R8.4). */
export enum ScopeSourceType {
  /** An SSM StringParameter holding a JSON list of scope ids. */
  SSM_PARAMETER = 'SSM_PARAMETER',
  /** A DynamoDB table the consumer owns. */
  DYNAMODB_TABLE = 'DYNAMODB_TABLE',
  /** A static list baked at synth. */
  STATIC = 'STATIC',
}

/** The source of the scope dimension's live values. */
export interface ScopeSource {
  readonly type: ScopeSourceType;
  /** SSM parameter name (SSM_PARAMETER), table name (DYNAMODB_TABLE), or unused. */
  readonly location?: string;
  /** Static scope ids (STATIC only). */
  readonly staticScopeIds?: string[];
}

/**
 * The injected scope dimension — what a "scope" is and where its values come
 * from (R8.4). Domain meaning enters ONLY through {@link label}; the construct
 * never names the consumer's concept (no `brand`, no `subject`).
 */
export interface ScopeDimension {
  /** Generic human label, e.g. 'scope' — NEVER a consumer domain term. */
  readonly label: string;
  readonly source: ScopeSource;
  /** Permission ids that are estate-level (no scope) rather than scope-level. */
  readonly estateLevelPermissionIds: string[];
}

/** The management permission required for each admin operation (R8.5, R10.1). */
export interface ManagementPermissionMap {
  readonly createRole: string;
  readonly deleteRole: string;
  readonly listRoles: string;
  readonly createAssignment: string;
  readonly deleteAssignment: string;
  readonly listAssignments: string;
}

/** How the management API authenticates the caller. */
export interface CallerIdentityConfig {
  /**
   * HTTPS URL of the consumer's published JWKS — the RS256 public keys the
   * caller's `web_identity` token is verified against. The two-token model: the
   * HMAC session cookie is validated ONLY at the CloudFront edge; behind the
   * edge the caller is identified by the asymmetric `web_identity` token alone,
   * so NO HMAC secret is read here.
   */
  readonly jwksUri: string;
  /**
   * Expected token issuer (`iss`). When set, the API rejects a token whose
   * issuer differs. ALSO supplies the OIDC provider host for the management
   * role's trust-policy condition key (`<host>:aud`/`:sub`), so it is REQUIRED
   * whenever {@link audience} or {@link trustedSubject} is set — a condition key
   * is a map key and must be a concrete synth-time string (the provider ARN,
   * which may be a token, cannot be split to derive it). @default no issuer check
   */
  readonly issuer?: string;
  /**
   * Expected token audience (`aud`). When set, the API rejects a token whose
   * audience differs. @default no audience check
   */
  readonly audience?: string;
  /** Cookie name carrying the `web_identity` token. @default '__Host-web_identity' */
  readonly sessionCookieName?: string;
  /**
   * The IAM OIDC provider ARN registered for the consumer's token issuer
   * (horton's JWKS issuer, NOT the IdP). The management role's trust policy pins
   * this provider so the Lambda can exchange the caller's token for the role via
   * `sts:AssumeRoleWithWebIdentity`.
   */
  readonly webIdentityOidcProviderArn: string;
  /**
   * The `sub` the management role's trust policy pins (the token subject allowed
   * to assume it). @default no sub condition (any token from the pinned provider
   * with the right audience may assume — the management-permission authZ in the
   * Lambda is the real gate)
   */
  readonly trustedSubject?: string;
}

/**
 * Props for {@link PermissionsAdmin}. Every domain-specific input is injected
 * here (R7, R8); no prop, resource name, or type names a consumer domain term.
 */
export interface PermissionsAdminProps {
  /** Canonical domain, for default resource names (as CognitoSessionBackend). */
  readonly domainName: string;

  /**
   * The consumer's existing CloudFront distribution.
   *
   * OPTIONAL. When supplied, the construct mounts two behaviours on it —
   * `/<prefix>/api/*` -> the HTTP API, and `/<prefix>/*` -> the SPA bucket —
   * i.e. the single-stack convenience path, where the distribution lives in the
   * SAME stack as this construct.
   *
   * OMIT it when the distribution lives in a DIFFERENT stack or region from the
   * management API (e.g. CloudFront's us-east-1 cert stack vs a regional API):
   * the construct then builds only the regional half (Lambda, HTTP API, role,
   * table access) and exposes {@link PermissionsAdmin.apiDomainName}. The
   * consumer mounts the `/<prefix>/api/*` behaviour itself in the
   * distribution's own stack — typically by publishing `apiDomainName` to the
   * distribution's region via a named SSM parameter and reading it region-
   * locally as an `HttpOrigin` (no cross-region references).
   */
  readonly distribution?: cloudfront.IDistribution;
  /**
   * The SPA asset bucket.
   *
   * REQUIRED when {@link distribution} is supplied (the construct deploys the
   * bundled SPA into it and serves it through that distribution). OMIT it in
   * standalone mode along with `distribution`: the consumer owns SPA hosting in
   * the distribution's own stack. Supplying one without the other is rejected.
   */
  readonly assetBucket?: s3.IBucket;
  /** Path prefix the admin SPA + API mount under. @default 'admin' */
  readonly pathPrefix?: string;

  /** Injected authority model — all domain meaning enters here (R7, R8). */
  readonly catalogue: PermissionCatalogue;
  readonly predefinedRoles: PredefinedRole[];
  /** Permission ids that can never be granted through this surface (R8.2, R11.2). */
  readonly rightsActLockout: string[];
  readonly scopeDimension: ScopeDimension;
  readonly managementPermissions: ManagementPermissionMap;

  /** Injected store — the construct reads/writes only through these refs (R8.3). */
  readonly roleTable: dynamodb.ITable;
  readonly assignmentTable: dynamodb.ITable;
  readonly bitRegistryTable: dynamodb.ITable;
  /**
   * Name of the assignment table's GSI that answers "is this role in use?" —
   * partition key `roleId`. Used by archive-not-delete (R11.4). @default 'roleId-index'
   */
  readonly assignmentRoleIndexName?: string;

  /** How the API authenticates the caller. */
  readonly callerIdentity: CallerIdentityConfig;

  /** Lambda log retention. @default RetentionDays.ONE_MONTH */
  readonly logRetention?: logs.RetentionDays;
  readonly removalPolicy?: core.RemovalPolicy;
}

/**
 * `PermissionsAdmin` — the write side of a reusable `(role, scope, assignment)`
 * authority model: a bundled admin SPA plus a regional management API.
 *
 * TWO MOUNTING MODES:
 *  - SINGLE-STACK (supply `distribution` + `assetBucket`): the construct mounts
 *    `/<prefix>/api/*` -> the HTTP API and `/<prefix>/*` -> the SPA bucket on
 *    the distribution, and deploys the bundled SPA. Use when the distribution
 *    lives in the same stack.
 *  - STANDALONE (omit both): the construct builds ONLY the regional half
 *    (Lambda, HTTP API, estate role, table access) and exposes `apiDomainName`.
 *    Use when the distribution is in a different stack/region (e.g. CloudFront's
 *    us-east-1 cert stack fronting a Sydney-regional API): the consumer
 *    publishes `apiDomainName` to the distribution's region via SSM and wires
 *    the `/<prefix>/api/*` `HttpOrigin` + SPA hosting there (no cross-region
 *    references). This keeps the estate role's trust policy pinned to a LOCAL
 *    OIDC provider rather than a cross-region one.
 *
 * The construct is DOMAIN-NEUTRAL (R7): it names no consumer concept. The
 * consumer injects the permission catalogue, predefined roles, scope dimension,
 * management-permission gating, and the DynamoDB store refs; the construct
 * carries the authority model without being forked.
 *
 * The regional management Lambda is the SOLE enforcement point (R9.3, R10, R11):
 * authN (session-cookie HMAC), authZ (per-op management permission), and the
 * server-side invariants (no-escalation, rights-act lockout, immutable
 * predefined roles, archive-not-delete), plus the custom-role bit registry
 * (R13) and an actor-stamped audit trail (R12). The SPA enforces nothing; it
 * reflects the caller's own permissions and hides what they lack (R9.2).
 */
export class PermissionsAdmin extends constructs.Construct {
  /** The regional management Lambda (sole enforcement point). */
  public readonly managementFunction: lambda.Function;
  /**
   * The estate management role the Lambda assumes per request (via the caller's
   * web_identity token). Holds the only grants on the three authority tables;
   * the Lambda's own role has none.
   */
  public readonly managementRole: core.aws_iam.Role;
  /** The regional HTTP API fronting the management Lambda. */
  public readonly httpApi: apigwv2.HttpApi;
  /**
   * The HTTP API's bare host (no scheme, no path), e.g.
   * `abc123.execute-api.ap-southeast-2.amazonaws.com`. In standalone mode
   * (no {@link PermissionsAdminProps.distribution}) the consumer publishes this
   * to the distribution's region via SSM and wires it as the `/<prefix>/api/*`
   * `HttpOrigin` there. Also set in single-stack mode, for symmetry.
   */
  public readonly apiDomainName: string;
  /** The path prefix the SPA + API mount under. */
  public readonly pathPrefix: string;

  constructor(scope: constructs.Construct, id: string, props: PermissionsAdminProps) {
    super(scope, id);

    const pathPrefix = (props.pathPrefix ?? 'admin').replace(/^\/+|\/+$/g, '');
    this.pathPrefix = pathPrefix;
    const sessionCookieName = props.callerIdentity.sessionCookieName ?? '__Host-web_identity';
    const assignmentRoleIndexName = props.assignmentRoleIndexName ?? 'roleId-index';
    const logRetention = props.logRetention ?? logs.RetentionDays.ONE_MONTH;

    // --- the estate MANAGEMENT role (two-token model, R16) -------------------
    // The management Lambda holds NO standing table grants. Instead it exchanges
    // the caller's RS256 `web_identity` token for THIS role via
    // sts:AssumeRoleWithWebIdentity and uses the scoped credentials for every
    // table call. The role is trusted by the consumer's own OIDC provider (its
    // JWKS issuer), pinned to the token audience (and optionally subject). Its
    // permission policy reaches exactly the three AUTHORITY tables — these are
    // estate-level stores (not brand-partitioned), so there is NO LeadingKeys
    // condition; the management-permission authZ in the Lambda is the gate on
    // WHO may write them.
    const oidcCondition: Record<string, Record<string, string>> = {};
    if (props.callerIdentity.audience || props.callerIdentity.trustedSubject) {
      // The condition key AWS uses for aud/sub on AssumeRoleWithWebIdentity is
      // `<provider-url-without-scheme>:aud` / `:sub` — and that provider URL is
      // the token ISSUER (the JWKS issuer == the OIDC provider url). Derive the
      // key prefix from `issuer` (a CONCRETE synth-time string), NOT by
      // Fn.split-ing the provider ARN: a condition key is a MAP KEY, and a map
      // key must resolve to a plain string at synth. When the provider ARN is a
      // token (e.g. a `Ref` to a provider created in the same stack — the normal
      // case for a standalone deployment co-located with its AuthInfrastructure),
      // splitting it yields an Fn::Select token, which CloudFormation refuses as
      // a map key ("used as the key in a map so must resolve to a string"). The
      // issuer is already concrete, so this both fixes that and is the same host.
      if (!props.callerIdentity.issuer) {
        throw new Error(
          'callerIdentity.issuer is required when audience or trustedSubject is set: '
          + 'it supplies the concrete OIDC provider host for the trust-policy condition key '
          + '(`<host>:aud`/`:sub`), which must be a synth-time string, not a token.',
        );
      }
      // Strip the URL scheme to get the bare host AWS keys the condition on.
      const providerHost = props.callerIdentity.issuer.replace(/^https?:\/\//, '');
      const conditions: Record<string, string> = {};
      if (props.callerIdentity.audience) {
        conditions[`${providerHost}:aud`] = props.callerIdentity.audience;
      }
      if (props.callerIdentity.trustedSubject) {
        conditions[`${providerHost}:sub`] = props.callerIdentity.trustedSubject;
      }
      oidcCondition.StringEquals = conditions;
    }
    const managementRole = new core.aws_iam.Role(this, 'ManagementRole', {
      assumedBy: new core.aws_iam.WebIdentityPrincipal(
        props.callerIdentity.webIdentityOidcProviderArn,
        Object.keys(oidcCondition).length ? oidcCondition : undefined,
      ),
      description: `permissions-admin estate management role for ${props.domainName} -- assumed per request via the caller's web_identity token`,
      maxSessionDuration: core.Duration.hours(1),
    });
    // Permission policy: exactly the three authority tables + the role-in-use GSI.
    managementRole.addToPolicy(new core.aws_iam.PolicyStatement({
      effect: core.aws_iam.Effect.ALLOW,
      actions: [
        'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query',
        'dynamodb:Scan', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem',
      ],
      resources: [
        props.roleTable.tableArn,
        props.bitRegistryTable.tableArn,
        props.assignmentTable.tableArn,
        `${props.assignmentTable.tableArn}/index/*`,
      ],
    }));
    this.managementRole = managementRole;

    // --- regional management Lambda (standard Lambda: env vars + full SDK) ----
    const fn = new lambda.Function(this, 'ManagementHandler', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      timeout: core.Duration.seconds(30),
      logRetention,
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/permissions-admin'), {
        bundling: {
          image: lambda.Runtime.PYTHON_3_12.bundlingImage,
          command: [
            'bash', '-c',
            'pip install -r requirements.txt -t /asset-output && cp -r . /asset-output',
          ],
        },
      }),
      environment: {
        ROLE_TABLE: props.roleTable.tableName,
        ASSIGNMENT_TABLE: props.assignmentTable.tableName,
        BIT_REGISTRY_TABLE: props.bitRegistryTable.tableName,
        ASSIGNMENT_ROLE_INDEX: assignmentRoleIndexName,
        // AuthN: verify the caller's RS256 web_identity token against the JWKS.
        JWKS_URI: props.callerIdentity.jwksUri,
        TOKEN_ISSUER: props.callerIdentity.issuer ?? '',
        TOKEN_AUDIENCE: props.callerIdentity.audience ?? '',
        SESSION_COOKIE_NAME: sessionCookieName,
        // Store access: assume this role per request (no standing grants).
        MANAGEMENT_ROLE_ARN: managementRole.roleArn,
        PATH_PREFIX: pathPrefix,
        CATALOGUE: JSON.stringify(props.catalogue.permissions),
        PREDEFINED_ROLES: JSON.stringify(props.predefinedRoles),
        RIGHTS_ACT_LOCKOUT: JSON.stringify(props.rightsActLockout),
        ESTATE_LEVEL_PERMS: JSON.stringify(props.scopeDimension.estateLevelPermissionIds),
        SCOPE_LABEL: props.scopeDimension.label,
        MANAGEMENT_PERMISSIONS: JSON.stringify(props.managementPermissions),
      },
    });
    this.managementFunction = fn;

    // The Lambda's OWN role gets NO table grants and NO secret read. Its only
    // added power is to assume the management role via web identity — which is a
    // public STS call needing no caller-side IAM, so there is nothing to grant
    // here. Store authority lives entirely on the assumed role above.

    // --- regional HTTP API ---------------------------------------------------
    const httpApi = new apigwv2.HttpApi(this, 'ManagementApi', {
      apiName: `permissions-admin-${props.domainName}`,
      createDefaultStage: true,
    });
    httpApi.addRoutes({
      path: '/{proxy+}',
      methods: [apigwv2.HttpMethod.ANY],
      integration: new HttpLambdaIntegration('ManagementIntegration', fn),
    });
    this.httpApi = httpApi;

    // The HTTP API's bare host, exposed so a standalone consumer can publish it
    // (e.g. to the distribution's region via SSM) and wire the `/<prefix>/api/*`
    // behaviour itself. Always set.
    const apiDomain = core.Fn.select(2, core.Fn.split('/', httpApi.apiEndpoint));
    this.apiDomainName = apiDomain;

    // --- CloudFront wiring: single-stack convenience ONLY --------------------
    // When `distribution` is supplied, the construct mounts the two behaviours
    // and deploys the SPA into the bucket — the single-stack path. When it is
    // omitted (standalone/cross-region mode) the construct builds only the
    // regional half above; the consumer mounts `/<prefix>/api/*` and owns SPA
    // hosting in the distribution's own stack, using `apiDomainName`.
    //
    // `assetBucket` is meaningful only alongside `distribution` (the SPA is
    // deployed into it AND served through that distribution), so the two are
    // paired: supplying exactly one is a wiring error and is rejected.
    if (Boolean(props.distribution) !== Boolean(props.assetBucket)) {
      throw new Error(
        'PermissionsAdmin: `distribution` and `assetBucket` must be supplied together ' +
        '(single-stack mode) or both omitted (standalone mode, consumer owns the ' +
        'CloudFront behaviour + SPA hosting and reads `apiDomainName`).',
      );
    }
    if (props.distribution && props.assetBucket) {
      const assetBucket = props.assetBucket;
      // --- CloudFront behaviours: /<prefix>/api/* -> HTTP API, /<prefix>/* -> S3 -
      (props.distribution as cloudfront.Distribution).addBehavior?.(
        `/${pathPrefix}/api/*`,
        new origins.HttpOrigin(apiDomain),
        {
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        },
      );
      (props.distribution as cloudfront.Distribution).addBehavior?.(
        `/${pathPrefix}/*`,
        origins.S3BucketOrigin.withOriginAccessControl(assetBucket),
        {
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        },
      );

      // --- bundled admin SPA under /<prefix>/ (R9, R14) ------------------------
      // Pre-built minimal static assets (no npm build at synth): bundled, served
      // from the injected bucket under the prefix, through the injected
      // distribution. The SPA reflects the caller's own permissions and hides
      // actions they lack — it enforces nothing (R9.3).
      new s3deploy.BucketDeployment(this, 'SpaDeployment', {
        sources: [s3deploy.Source.asset(path.join(__dirname, 'permissions-admin-spa'))],
        destinationBucket: assetBucket,
        destinationKeyPrefix: `${pathPrefix}/`,
        distribution: props.distribution,
        distributionPaths: [`/${pathPrefix}/*`],
      });
    }
  }
}
