import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_secretsmanager as secretsmanager,
  aws_kms as kms,
  aws_iam as iam,
  RemovalPolicy,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface AuthSecretManagerProps {
  readonly domainName: string;
  readonly tableName: string;
  readonly tableRegion: string;
  readonly azureTenantId: string;
  readonly azureClientId: string;
  readonly stsAudience: string;
  readonly cookieDomain?: string;
  /** Domains permitted as the request host during OAuth callback. @default [domainName] */
  readonly allowedDomains?: string[];
  readonly securityAlertsTopicArn?: string;
  readonly autoRevokeOnReuse?: boolean;
  readonly jwtClaimsWhitelist?: string[];
  /** URL for the post-auth identity hook. Called after token exchange to resolve app-specific claims. @default undefined (no hook) */
  readonly postAuthHookUrl?: string;
  /** Timeout in seconds for the post-auth hook call. @default 3 */
  readonly postAuthHookTimeout?: number;
  /** Whether to deny auth if the hook fails or is unavailable. @default true */
  readonly postAuthHookFailClosed?: boolean;
  /** Whether to store refresh tokens for silent session renewal. @default false */
  readonly enableRefresh?: boolean;
  /**
   * Ceiling (bytes) on the assembled HMAC session token. When set, written into
   * the config secret as `scope_token_max_bytes`; the mint refuses an
   * over-budget token rather than truncating. Omitted from the secret when
   * unset, so the mint's built-in 7168-byte default applies and the secret
   * template is byte-for-byte unchanged for existing consumers.
   */
  readonly scopeTokenMaxBytes?: number;
  /**
   * Enable the RS256 **web-identity token** half of the two-token model. When
   * true, an asymmetric KMS signing key (RSA_2048, SIGN_VERIFY) is created and
   * the mint ALSO issues a horton-signed RS256 JWT — alongside the HMAC session
   * cookie — carrying the same principal-tags brand claim, for
   * `sts:AssumeRoleWithWebIdentity`. The private key never leaves KMS
   * (`kms:Sign`); the public half is served at {@link jwksPath}. Default OFF, so
   * existing consumers synthesise no new key and mint no second token.
   * @default false
   */
  readonly enableWebIdentityToken?: boolean;
  /**
   * Issuer (`iss`) and audience (`aud`) stamped on the RS256 web-identity token,
   * and the `url` of the IAM OIDC provider that trusts it. Required when
   * {@link enableWebIdentityToken} is true. Typically the JWKS-hosting origin,
   * e.g. `https://admin.example.com`.
   */
  readonly webIdentityIssuer?: string;
}

export class AuthSecretManager extends constructs.Construct {
  public readonly kmsKey: kms.Key;
  public readonly configSecret: secretsmanager.Secret;
  public readonly kvs: cloudfront.KeyValueStore;
  /**
   * Asymmetric (RSA_2048 SIGN_VERIFY) KMS key the mint uses to sign the RS256
   * web-identity token. Only created when `enableWebIdentityToken` is true;
   * undefined otherwise.
   */
  public readonly webIdentityKey?: kms.Key;

  constructor(scope: constructs.Construct, id: string, props: AuthSecretManagerProps) {
    super(scope, id);

    this.kmsKey = new kms.Key(this, 'KmsKey', {
      description: 'KMS key for CloudFront auth secret encryption',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.kmsKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchLogs',
      principals: [new iam.ServicePrincipal(`logs.${core.Stack.of(this).region}.amazonaws.com`)],
      actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:CreateGrant', 'kms:DescribeKey'],
      resources: ['*'],
      conditions: {
        ArnLike: {
          'kms:EncryptionContext:aws:logs:arn': `arn:aws:logs:${core.Stack.of(this).region}:${core.Stack.of(this).account}:log-group:*`,
        },
      },
    }));

    const jwtClaimsWhitelist = props.jwtClaimsWhitelist ?? [
      'oid', 'tid', 'sub', 'email', 'name', 'preferred_username', 'groups', 'roles', 'amr',
    ];

    // RS256 web-identity half (opt-in). An asymmetric KMS key whose private
    // half never leaves KMS; the mint signs the role-assumption token with
    // kms:Sign and the public half is published as a JWKS. Single regional key
    // (not multi-Region): the mint already reads its config from a fixed region
    // and signs once per login, so a cross-region kms:Sign is acceptable and
    // avoids per-replica key cost + rotation complexity.
    if (props.enableWebIdentityToken) {
      if (!props.webIdentityIssuer) {
        throw new Error(
          'enableWebIdentityToken requires webIdentityIssuer (the iss/aud for the '
          + 'RS256 token and the OIDC provider url).',
        );
      }
      this.webIdentityKey = new kms.Key(this, 'WebIdentityKey', {
        description: 'Asymmetric RS256 signing key for the web-identity token (AssumeRoleWithWebIdentity)',
        keySpec: kms.KeySpec.RSA_2048,
        keyUsage: kms.KeyUsage.SIGN_VERIFY,
        // Asymmetric keys do not support automatic rotation; rotation is a
        // deliberate new-key + JWKS-overlap operation.
        enableKeyRotation: false,
        removalPolicy: RemovalPolicy.RETAIN,
      });
    }

    const configSecretName = `cloudfront-auth-config-${props.domainName}`;
    const configTemplate: Record<string, string> = {
      azure_tenant_id: props.azureTenantId,
      azure_client_id: props.azureClientId,
      redirect_uri: `https://${props.domainName}/oauth2/callback`,
      sts_audience: props.stsAudience,
      dynamodb_table_name: props.tableName,
      dynamodb_region: props.tableRegion,
      security_alerts_topic_arn: props.securityAlertsTopicArn || '',
      auto_revoke_on_reuse: props.autoRevokeOnReuse ? 'true' : 'false',
      jwt_claims_whitelist: JSON.stringify(jwtClaimsWhitelist),
      allowed_domains: JSON.stringify(props.allowedDomains ?? [props.domainName]),
      cookie_domain: props.cookieDomain || '',
      post_auth_hook_url: props.postAuthHookUrl || '',
      post_auth_hook_timeout: String(props.postAuthHookTimeout ?? 3),
      post_auth_hook_fail_closed: (props.postAuthHookFailClosed ?? true) ? 'true' : 'false',
      enable_refresh: props.enableRefresh ? 'true' : 'false',
    };
    // Only emitted when explicitly set, so the mint's built-in 7168 default
    // applies and the secret template is byte-for-byte unchanged otherwise.
    if (props.scopeTokenMaxBytes !== undefined) {
      configTemplate.scope_token_max_bytes = String(props.scopeTokenMaxBytes);
    }
    // RS256 web-identity half: give the mint the asymmetric key id + issuer so
    // it can also sign the role-assumption token. Only present when enabled, so
    // the secret template is byte-for-byte unchanged for existing consumers and
    // the mint treats the feature as off when the keys are absent.
    if (props.enableWebIdentityToken && this.webIdentityKey) {
      configTemplate.web_identity_signing_key_id = this.webIdentityKey.keyId;
      configTemplate.web_identity_issuer = props.webIdentityIssuer!;
    }
    this.configSecret = new secretsmanager.Secret(this, 'ConfigSecret', {
      secretName: configSecretName,
      encryptionKey: this.kmsKey,
      generateSecretString: {
        secretStringTemplate: JSON.stringify(configTemplate),
        generateStringKey: 'hmac_key',
        excludePunctuation: true,
        passwordLength: 64,
        requireEachIncludedType: false,
      },
      description: 'Configuration and HMAC secret for CloudFront authentication',
    });

    this.kvs = new cloudfront.KeyValueStore(this, 'AuthKVS', {
      comment: 'HMAC secret and session revocation denylist',
    });
  }
}
