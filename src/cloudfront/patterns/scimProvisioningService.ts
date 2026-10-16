import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_dynamodb as dynamodb,
  aws_kms as kms,
  aws_lambda as lambda,
  aws_logs as logs,
  aws_secretsmanager as secrets,
  RemovalPolicy,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

/**
 * Provisioning-channel authentication mode.
 *
 * - `OAUTH_CLIENT_CREDENTIALS` (default): the IdP exchanges a client id + secret
 *   at the token endpoint for a short-lived, KMS-signed JWT, which it presents on
 *   SCIM calls. No long-lived secret on the wire.
 * - `AWS_IAM`: the Function URL enforces SigV4; the caller is an AWS principal.
 *   Genuinely secretless. No token endpoint.
 * - `WIF`: the IdP federates (RFC 7523 JWT bearer assertion); no stored secret.
 *   A designed-in upgrade, enabled where the IdP exposes WIF for a custom app.
 * - `STATIC_BEARER`: constant-time compare against a Secrets Manager secret.
 *   The legacy path (Microsoft no longer onboards it); opt-in only.
 */
export enum ScimAuthMode {
  OAUTH_CLIENT_CREDENTIALS = 'OAUTH_CLIENT_CREDENTIALS',
  AWS_IAM = 'AWS_IAM',
  WIF = 'WIF',
  STATIC_BEARER = 'STATIC_BEARER',
}

/** Trust parameters for the WIF (RFC 7523) assertion exchange. */
export interface ScimWifConfig {
  /** The IdP assertion issuer, e.g. `https://login.microsoftonline.com/<tid>/v2.0`. */
  readonly assertionIssuer: string;
  /** The IdP JWKS URI, e.g. `https://login.microsoftonline.com/<tid>/discovery/v2.0/keys`. */
  readonly assertionJwksUri: string;
  /** Expected `aud` on the assertion (the Workload Identity App ID). */
  readonly expectedAudience: string;
  /** Expected `azp` on the assertion (the Provisioning Client 1P App ID). */
  readonly expectedAzp: string;
}

/**
 * Props for {@link ScimProvisioningService}. Every consumer/IdP/domain value is
 * a prop with a generic default; nothing project-specific is baked in.
 */
export interface ScimProvisioningServiceProps {
  /** Auth mode for the provisioning channel. @default OAUTH_CLIENT_CREDENTIALS */
  readonly authMode?: ScimAuthMode;
  /** SCIM base path. @default '/scim/v2' */
  readonly scimBasePath?: string;
  /** OAuth token endpoint path (OAUTH_CLIENT_CREDENTIALS / WIF). @default '/oauth2/token' */
  readonly tokenEndpointPath?: string;
  /** JWKS path where the token signing public key is served. @default '/.well-known/jwks.json' */
  readonly jwksPath?: string;
  /** Issued access-token lifetime. @default Duration.hours(1) */
  readonly accessTokenValidity?: core.Duration;
  /**
   * Issuer (`iss`) stamped on issued tokens; also the audience the SCIM handler
   * requires. @default derived from the Function URL at deploy time.
   */
  readonly tokenIssuer?: string;
  /** WIF trust parameters. Required when {@link authMode} is `WIF`. */
  readonly wif?: ScimWifConfig;
  /** DynamoDB table name. @default CDK-auto-generated. */
  readonly tableName?: string;
  /** Removal policy for table + any secret. @default RETAIN_ON_UPDATE_OR_DELETE */
  readonly removalPolicy?: RemovalPolicy;
  /** Log retention. @default RetentionDays.ONE_MONTH */
  readonly logRetention?: logs.RetentionDays;
  /** Lambda timeout. @default Duration.seconds(30) */
  readonly timeout?: core.Duration;
}

/**
 * A generic, reusable SCIM 2.0 provisioning service: an IdP provisions users and
 * groups into a construct-owned DynamoDB table over SCIM 2.0, authenticating with
 * short-lived OAuth 2.0 client-credentials tokens minted by a token endpoint the
 * construct hosts itself. A consuming application reads the table with a single
 * `GetItem(USER#<externalId>)` to resolve an external id to `active` + a group-id
 * list.
 *
 * Consumer- and IdP-agnostic: pass props. horton (ADR-0003.5) is the first
 * adopter. CloudFront/WAF/origin-access is out of scope; adopt {@link functionUrl}
 * as an origin in a downstream distribution stack.
 */
export class ScimProvisioningService extends constructs.Construct {
  /** Base HTTPS URL of the service (Function URL). */
  public readonly functionUrl: string;
  /** SCIM base URL (functionUrl + scimBasePath). */
  public readonly scimUrl: string;
  /** Token endpoint URL (OAUTH_CLIENT_CREDENTIALS / WIF); undefined otherwise. */
  public readonly tokenUrl?: string;
  /** JWKS URL (where a token endpoint exists); undefined otherwise. */
  public readonly jwksUrl?: string;
  /** The provisioned-directory table; grant your consumer read on it. */
  public readonly table: dynamodb.ITable;
  public readonly tableArn: string;
  /** OAUTH_CLIENT_CREDENTIALS: the IdP's client-secret ARN (value set out-of-band). */
  public readonly clientSecretArn?: string;
  /** STATIC_BEARER only: the bearer-secret ARN. */
  public readonly staticBearerSecretArn?: string;

  constructor(scope: constructs.Construct, id: string, props: ScimProvisioningServiceProps = {}) {
    super(scope, id);

    const authMode = props.authMode ?? ScimAuthMode.OAUTH_CLIENT_CREDENTIALS;
    const scimBasePath = props.scimBasePath ?? '/scim/v2';
    const tokenEndpointPath = props.tokenEndpointPath ?? '/oauth2/token';
    const jwksPath = props.jwksPath ?? '/.well-known/jwks.json';
    const removalPolicy = props.removalPolicy ?? RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE;
    const usesTokenEndpoint = authMode === ScimAuthMode.OAUTH_CLIENT_CREDENTIALS || authMode === ScimAuthMode.WIF;

    if (authMode === ScimAuthMode.WIF && !props.wif) {
      throw new Error('ScimProvisioningService: authMode WIF requires the `wif` trust parameters.');
    }

    // --- store ---------------------------------------------------------------
    const table = new dynamodb.Table(this, 'Table', {
      tableName: props.tableName,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy,
    });
    table.addGlobalSecondaryIndex({
      indexName: 'GSI1',
      partitionKey: { name: 'gsi1pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'gsi1sk', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    table.addGlobalSecondaryIndex({
      indexName: 'GSI2',
      partitionKey: { name: 'gsi2pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'gsi2sk', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    this.table = table;
    this.tableArn = table.tableArn;

    // --- signing key (OAUTH / WIF mint + verify) -----------------------------
    let signingKey: kms.Key | undefined;
    if (usesTokenEndpoint) {
      signingKey = new kms.Key(this, 'SigningKey', {
        description: 'SCIM provisioning access-token signing key (RS256)',
        keySpec: kms.KeySpec.RSA_2048,
        keyUsage: kms.KeyUsage.SIGN_VERIFY,
        removalPolicy,
      });
    }

    // --- secrets -------------------------------------------------------------
    let clientSecret: secrets.Secret | undefined;
    let staticBearerSecret: secrets.Secret | undefined;
    if (authMode === ScimAuthMode.OAUTH_CLIENT_CREDENTIALS) {
      // No generated value: an empty GenerateSecretString would make Secrets
      // Manager mint a random value, which is not what we want. We seed an
      // explicit placeholder; the operator overwrites it with the real client
      // secret out-of-band (never through automated tooling).
      clientSecret = new secrets.Secret(this, 'ClientSecret', {
        description: 'SCIM provisioning OAuth client secret (set out-of-band)',
        secretStringValue: core.SecretValue.unsafePlainText('REPLACE_ME_OUT_OF_BAND'),
        removalPolicy,
      });
      this.clientSecretArn = clientSecret.secretArn;
    }
    if (authMode === ScimAuthMode.STATIC_BEARER) {
      staticBearerSecret = new secrets.Secret(this, 'StaticBearerSecret', {
        description: 'SCIM provisioning static bearer token (legacy; set out-of-band)',
        secretStringValue: core.SecretValue.unsafePlainText('REPLACE_ME_OUT_OF_BAND'),
        removalPolicy,
      });
      this.staticBearerSecretArn = staticBearerSecret.secretArn;
    }

    // --- handler -------------------------------------------------------------
    const tokenIssuer = props.tokenIssuer ?? 'https://scim-provisioning.invalid';
    const fn = new lambda.Function(this, 'Handler', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/scim-provisioning')),
      timeout: props.timeout ?? core.Duration.seconds(30),
      logRetention: props.logRetention ?? logs.RetentionDays.ONE_MONTH,
      environment: {
        AUTH_MODE: authMode,
        SCIM_BASE_PATH: scimBasePath,
        TOKEN_ENDPOINT_PATH: tokenEndpointPath,
        JWKS_PATH: jwksPath,
        TABLE_NAME: table.tableName,
        TOKEN_ISSUER: tokenIssuer,
        ACCESS_TOKEN_TTL: String((props.accessTokenValidity ?? core.Duration.hours(1)).toSeconds()),
        ...(signingKey ? { SIGNING_KEY_ID: signingKey.keyId } : {}),
        ...(clientSecret ? { CLIENT_SECRET_ARN: clientSecret.secretArn } : {}),
        ...(staticBearerSecret ? { STATIC_BEARER_ARN: staticBearerSecret.secretArn } : {}),
        ...(props.wif ? {
          WIF_ASSERTION_ISSUER: props.wif.assertionIssuer,
          WIF_ASSERTION_JWKS_URI: props.wif.assertionJwksUri,
          WIF_EXPECTED_AUDIENCE: props.wif.expectedAudience,
          WIF_EXPECTED_AZP: props.wif.expectedAzp,
        } : {}),
      },
    });

    // --- least-privilege IAM -------------------------------------------------
    // DynamoDB: item ops + query on the table and its indexes only.
    table.grantReadWriteData(fn);
    // KMS: sign + read public key on the OWN key only.
    if (signingKey) {
      signingKey.grant(fn, 'kms:Sign', 'kms:GetPublicKey');
    }
    // Secrets Manager: read the OWN secret only.
    if (clientSecret) {
      clientSecret.grantRead(fn);
    }
    if (staticBearerSecret) {
      staticBearerSecret.grantRead(fn);
    }

    // --- front door ----------------------------------------------------------
    const fnUrl = fn.addFunctionUrl({
      authType: authMode === ScimAuthMode.AWS_IAM
        ? lambda.FunctionUrlAuthType.AWS_IAM
        : lambda.FunctionUrlAuthType.NONE,
    });

    this.functionUrl = fnUrl.url;
    this.scimUrl = core.Fn.join('', [fnUrl.url, scimBasePath.replace(/^\//, '')]);
    if (usesTokenEndpoint) {
      this.tokenUrl = core.Fn.join('', [fnUrl.url, tokenEndpointPath.replace(/^\//, '')]);
      this.jwksUrl = core.Fn.join('', [fnUrl.url, jwksPath.replace(/^\//, '')]);
    }

    new core.CfnOutput(this, 'FunctionUrl', { value: fnUrl.url, description: 'SCIM provisioning Function URL' });
    new core.CfnOutput(this, 'ScimTableName', { value: table.tableName, description: 'SCIM provisioning table name' });
  }
}
