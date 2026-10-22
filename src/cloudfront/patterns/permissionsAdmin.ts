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
   * Secrets Manager ARN of the HMAC secret the minted `__Host-auth_session`
   * cookie is signed with — the API verifies the cookie against it.
   */
  readonly sessionHmacSecretArn: string;
  /** Cookie name carrying the session token. @default '__Host-auth_session' */
  readonly sessionCookieName?: string;
}

/**
 * Props for {@link PermissionsAdmin}. Every domain-specific input is injected
 * here (R7, R8); no prop, resource name, or type names a consumer domain term.
 */
export interface PermissionsAdminProps {
  /** Canonical domain, for default resource names (as CognitoSessionBackend). */
  readonly domainName: string;

  /** The consumer's existing CloudFront distribution and asset bucket. */
  readonly distribution: cloudfront.IDistribution;
  readonly assetBucket: s3.IBucket;
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
 * authority model: a bundled admin SPA plus a regional management API, served
 * through the consumer's existing CloudFront distribution under a path prefix.
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
  /** The regional HTTP API fronting the management Lambda. */
  public readonly httpApi: apigwv2.HttpApi;
  /** The path prefix the SPA + API mount under. */
  public readonly pathPrefix: string;

  constructor(scope: constructs.Construct, id: string, props: PermissionsAdminProps) {
    super(scope, id);

    const pathPrefix = (props.pathPrefix ?? 'admin').replace(/^\/+|\/+$/g, '');
    this.pathPrefix = pathPrefix;
    const sessionCookieName = props.callerIdentity.sessionCookieName ?? '__Host-auth_session';
    const assignmentRoleIndexName = props.assignmentRoleIndexName ?? 'roleId-index';
    const logRetention = props.logRetention ?? logs.RetentionDays.ONE_MONTH;

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
        SESSION_HMAC_SECRET_ARN: props.callerIdentity.sessionHmacSecretArn,
        SESSION_COOKIE_NAME: sessionCookieName,
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

    // --- least-privilege store grants (R8.3, R16) ----------------------------
    // Roles are read + written (create/archive); bit registry read + written
    // (allocate/retire); assignments read + written (grant/revoke), plus a read
    // on the "role in use?" GSI for archive-not-delete.
    props.roleTable.grantReadWriteData(fn);
    props.bitRegistryTable.grantReadWriteData(fn);
    props.assignmentTable.grantReadWriteData(fn);

    // Read the session HMAC secret to verify the caller's cookie.
    fn.addToRolePolicy(new core.aws_iam.PolicyStatement({
      effect: core.aws_iam.Effect.ALLOW,
      actions: ['secretsmanager:GetSecretValue'],
      resources: [props.callerIdentity.sessionHmacSecretArn],
    }));

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

    // --- CloudFront behaviours: /<prefix>/api/* -> HTTP API, /<prefix>/* -> S3 -
    const apiDomain = core.Fn.select(2, core.Fn.split('/', httpApi.apiEndpoint));
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
      origins.S3BucketOrigin.withOriginAccessControl(props.assetBucket),
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
      destinationBucket: props.assetBucket,
      destinationKeyPrefix: `${pathPrefix}/`,
      distribution: props.distribution,
      distributionPaths: [`/${pathPrefix}/*`],
    });
  }
}
