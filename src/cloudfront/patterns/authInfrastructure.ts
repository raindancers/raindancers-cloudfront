import * as core from 'aws-cdk-lib';
import {
  aws_iam as iam,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';
import { AuthLambdaFunctions } from '../auth/authLambdaFunctions';
import { AuthSecretManager } from '../auth/authSecretManager';
import { AuthSecurityTable } from '../authSecurityTable';
import { AuditLogArchive } from '../logging/auditLogArchive';
import { SsmCrossRegionWriter } from '../ssmCrossRegionWriter';

const AZURE_RESERVED_WORDS = [
  'admin', 'administrator', 'root', 'sys', 'system', 'guest', 'public',
  'user', 'users', 'microsoft', 'windows', 'office', 'azure', 'exchange',
  'sharepoint', 'teams', 'support', 'help', 'service',
];

function validateGroupNames(groups: string[]): void {
  const invalidGroups: string[] = [];
  groups.forEach(group => {
    const reservedWord = AZURE_RESERVED_WORDS.find(word => {
      if (group.toLowerCase() === word) return true;
      return new RegExp(`\\b${word}\\b`, 'i').test(group);
    });
    if (reservedWord) {
      invalidGroups.push(`'${group}' (contains reserved word '${reservedWord}')`);
    }
  });
  if (invalidGroups.length > 0) {
    throw new Error(
      `Invalid Azure AD group names detected:\n${invalidGroups.join('\n')}\n\n` +
      'Azure AD blocks group names containing reserved words.',
    );
  }
}

// SHA-1 fingerprint of DigiCert Global Root G2 (Azure AD root CA). Stable 10-20 years.
const AZURE_AD_THUMBPRINT = '6938fd4d98bab03faadb97b34396831e3780aea1';

export interface AppSpec {
  readonly name: string;
  readonly groups?: string[];
}

export interface AuthInfrastructureProps {
  readonly ssmParamPrefix?: string;
  readonly zoneName: string;
  /** Domains permitted as the request host during OAuth callback (e.g. subdomains served by the distribution). @default [zoneName] */
  readonly allowedDomains?: string[];
  readonly tenantId: string;
  readonly clientId: string;
  readonly oauth2CallbackRoleName: string;
  readonly appSpec: AppSpec;
  readonly cookieDomain?: string;
  readonly securityAlertsTopicArn?: string;
  readonly sessionRevocationTopicArn?: string;
  readonly autoRevokeOnReuse?: boolean;
  readonly jwtClaimsWhitelist?: string[];
  readonly hmacSecretRotationSchedule?: core.Duration;
  readonly auditLogRetentionDays?: number;
  readonly auditArchiveRetentionDays?: number;
  readonly auditLogBucketName?: string;
  readonly auditLogDatabaseName?: string;
  /** ARN of an existing OIDC provider to reuse (skips creating a new one). Use when the same tenant already has a provider in this account. */
  readonly existingOidcProviderArn?: string;
  readonly removalPolicy?: core.RemovalPolicy;
  /** URL for the post-auth identity hook. @default undefined */
  readonly postAuthHookUrl?: string;
  /** Timeout in seconds for the post-auth hook. @default 3 */
  readonly postAuthHookTimeout?: number;
  /** Fail closed if hook is unavailable. @default true */
  readonly postAuthHookFailClosed?: boolean;
  /** Enable refresh token storage. @default false */
  readonly enableRefresh?: boolean;
  /**
   * Ceiling (bytes) on the assembled HMAC session token. Over this, the mint is
   * REFUSED (explicit error, logged) — never truncated, never with resolver
   * role claims or scope principal tags dropped to fit. Mirrors the Cognito
   * session backend's `scopeTokenMaxBytes`.
   * @default 7168 (within the ~8 KB browser cookie budget)
   */
  readonly scopeTokenMaxBytes?: number;
  /**
   * Enable the RS256 **web-identity token** half of the two-token model. When
   * true: an asymmetric KMS signing key is created, the mint also issues a
   * horton-signed RS256 JWT (for `sts:AssumeRoleWithWebIdentity`) carrying the
   * principal-tags brand claim, a JWKS is served at {@link jwksPath}, and a
   * second IAM OIDC provider is created whose url is {@link webIdentityIssuer}
   * (NOT Entra) — exposed as {@link webIdentityOidcProviderArn} so role trust
   * policies can pin it. Default OFF: no new key, no second token, no provider.
   * @default false
   */
  readonly enableWebIdentityToken?: boolean;
  /**
   * Issuer (`iss`/`aud`) for the RS256 web-identity token and the url of its
   * OIDC provider. Also the JWKS-hosting origin. Required when
   * {@link enableWebIdentityToken} is true, e.g. `https://admin.example.com`.
   */
  readonly webIdentityIssuer?: string;
  /**
   * Path the JWKS (the web-identity key's public half) is served at.
   * @default '/.well-known/jwks.json'
   */
  readonly jwksPath?: string;
}

export class AuthInfrastructure extends constructs.Construct {
  public readonly configSecretArn: string;
  public readonly kmsKeyArn: string;
  public readonly authTableArn: string;
  public readonly kvsArn: string;
  public readonly tenantId: string;
  public readonly clientId: string;
  public readonly oauth2CallbackRoleName: string;
  public readonly oidcProvider: iam.IOpenIdConnectProvider;
  /**
   * ARN of the IAM OIDC provider that trusts the RS256 web-identity token
   * (url = `webIdentityIssuer`). Pin role trust policies to this. Only set when
   * `enableWebIdentityToken` is true.
   */
  public readonly webIdentityOidcProviderArn?: string;
  /**
   * ARN of the asymmetric KMS key the mint signs the web-identity token with.
   * Only set when `enableWebIdentityToken` is true.
   */
  public readonly webIdentityKeyArn?: string;

  constructor(scope: constructs.Construct, id: string, props: AuthInfrastructureProps) {
    super(scope, id);

    if (props.appSpec.groups && props.appSpec.groups.length > 0) {
      validateGroupNames(props.appSpec.groups);
    }

    this.tenantId = props.tenantId;
    this.clientId = props.clientId;
    this.oauth2CallbackRoleName = props.oauth2CallbackRoleName;

    const authSecurityTable = new AuthSecurityTable(this, 'AuthSecurityTable', {
      tableName: `auth-security-${props.zoneName}`,
      removalPolicy: props.removalPolicy ?? core.RemovalPolicy.RETAIN,
    });

    const secretManager = new AuthSecretManager(this, 'SecretManager', {
      domainName: props.zoneName,
      allowedDomains: props.allowedDomains,
      tableName: authSecurityTable.table.tableName,
      tableRegion: core.Stack.of(this).region,
      azureTenantId: props.tenantId,
      azureClientId: props.clientId,
      stsAudience: 'api://AzureADTokenExchange',
      securityAlertsTopicArn: props.securityAlertsTopicArn,
      autoRevokeOnReuse: props.autoRevokeOnReuse,
      jwtClaimsWhitelist: props.jwtClaimsWhitelist,
      cookieDomain: props.cookieDomain,
      postAuthHookUrl: props.postAuthHookUrl,
      postAuthHookTimeout: props.postAuthHookTimeout,
      postAuthHookFailClosed: props.postAuthHookFailClosed,
      enableRefresh: props.enableRefresh,
      scopeTokenMaxBytes: props.scopeTokenMaxBytes,
      enableWebIdentityToken: props.enableWebIdentityToken,
      webIdentityIssuer: props.webIdentityIssuer,
    });

    const auditLogRetentionDays = props.auditLogRetentionDays ?? 30;
    const auditArchiveRetentionDays = props.auditArchiveRetentionDays ?? 365;

    const lambdaFunctions = new AuthLambdaFunctions(this, 'LambdaFunctions', {
      configSecret: secretManager.configSecret,
      kmsKey: secretManager.kmsKey,
      kvs: secretManager.kvs,
      authTable: authSecurityTable.table,
      rotationSchedule: props.hmacSecretRotationSchedule,
      sessionRevocationTopicArn: props.sessionRevocationTopicArn,
      logRetentionDays: auditLogRetentionDays,
    });

    new AuditLogArchive(this, 'AuditLogArchive', {
      logGroupNames: lambdaFunctions.logGroups.map(lg => lg.logGroupName),
      kmsKey: secretManager.kmsKey,
      retentionDays: auditLogRetentionDays,
      archiveRetentionDays: auditArchiveRetentionDays,
      bucketName: props.auditLogBucketName ?? `auth-audit-logs-${core.Stack.of(this).account}-${core.Stack.of(this).region}`,
      databaseName: props.auditLogDatabaseName ?? 'auth_audit_logs',
      removalPolicy: props.removalPolicy ?? core.RemovalPolicy.RETAIN,
    });

    let oidcProvider: iam.IOpenIdConnectProvider;
    if (props.existingOidcProviderArn) {
      oidcProvider = iam.OpenIdConnectProvider.fromOpenIdConnectProviderArn(this, 'OidcProvider', props.existingOidcProviderArn);
    } else {
      oidcProvider = new iam.OpenIdConnectProvider(this, 'OidcProvider', {
        url: `https://login.microsoftonline.com/${props.tenantId}/v2.0`,
        clientIds: [props.clientId],
        thumbprints: [AZURE_AD_THUMBPRINT],
      });
    }

    this.configSecretArn = secretManager.configSecret.secretArn;
    this.kmsKeyArn = secretManager.kmsKey.keyArn;
    this.authTableArn = authSecurityTable.table.tableArn;
    this.kvsArn = secretManager.kvs.keyValueStoreArn;
    this.oidcProvider = oidcProvider;

    // RS256 web-identity half (opt-in): a SECOND OIDC provider whose url is the
    // horton JWKS issuer — the one STS verifies the role-assumption token
    // against. Distinct from the Entra provider above (which stays for its own
    // purpose). clientIds = [webIdentityIssuer] because the mint stamps
    // aud == iss (self-audience). No static thumbprint: the issuer is an HTTPS
    // origin with a current public TLS cert, so the thumbprint is derived.
    if (props.enableWebIdentityToken && secretManager.webIdentityKey) {
      const webIdentityProvider = new iam.OpenIdConnectProvider(this, 'WebIdentityOidcProvider', {
        url: props.webIdentityIssuer!,
        clientIds: [props.webIdentityIssuer!],
      });
      this.webIdentityOidcProviderArn = webIdentityProvider.openIdConnectProviderArn;
      this.webIdentityKeyArn = secretManager.webIdentityKey.keyArn;
    }

    const prefix = props.ssmParamPrefix ?? `/auth/${props.zoneName}`;

    const ssmParams: Record<string, string> = {
      configSecretArn: secretManager.configSecret.secretArn,
      kmsKeyArn: secretManager.kmsKey.keyArn,
      authTableArn: authSecurityTable.table.tableArn,
      kvsArn: secretManager.kvs.keyValueStoreArn,
      tenantId: props.tenantId,
      clientId: props.clientId,
      oauth2CallbackRoleName: props.oauth2CallbackRoleName,
    };
    // Publish the web-identity key ARN + its region only when the feature is on,
    // so the consumer (securedCloudFront) grants kms:Sign on it and the SSM
    // param set is unchanged for existing consumers.
    if (props.enableWebIdentityToken && secretManager.webIdentityKey) {
      ssmParams.webIdentityKeyArn = secretManager.webIdentityKey.keyArn;
      ssmParams.webIdentityKeyRegion = core.Stack.of(this).region;
    }

    new SsmCrossRegionWriter(this, 'SsmWriter', {
      prefix: prefix,
      region: 'us-east-1',
      params: ssmParams,
    });
  }
}
