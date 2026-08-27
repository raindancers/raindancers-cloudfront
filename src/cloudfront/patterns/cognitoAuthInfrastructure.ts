import * as core from 'aws-cdk-lib';
import {
  aws_cognito as cognito,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';
import { AppSpec } from './authInfrastructure';
import { CognitoCustomerPool } from './cognitoCustomerPool';
import { CognitoSessionBackend } from './cognitoSessionBackend';

export interface CognitoAuthInfrastructureProps {
  readonly ssmParamPrefix?: string;
  readonly zoneName: string;
  readonly appSpec: AppSpec;
  readonly cognitoDomainPrefix: string;
  readonly securityAlertsTopicArn?: string;
  readonly sessionRevocationTopicArn?: string;
  readonly autoRevokeOnReuse?: boolean;
  readonly jwtClaimsWhitelist?: string[];
  readonly hmacSecretRotationSchedule?: core.Duration;
  readonly auditLogRetentionDays?: number;
  readonly auditArchiveRetentionDays?: number;
  readonly removalPolicy?: core.RemovalPolicy;
}

/**
 * Convenience facade that composes a {@link CognitoCustomerPool} (identity
 * provider) and a {@link CognitoSessionBackend} (session substrate) with the
 * original bundled defaults. Existing consumers keep the same public API.
 *
 * New projects that need finer control (per-brand app clients, SMS MFA, advanced
 * security, identity-pool ABAC, a separately-managed session backend) should use
 * {@link CognitoCustomerPool} and {@link CognitoSessionBackend} directly.
 */
export class CognitoAuthInfrastructure extends constructs.Construct {
  public readonly configSecretArn: string;
  public readonly kmsKeyArn: string;
  public readonly authTableArn: string;
  public readonly kvsArn: string;
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly cognitoDomain: cognito.UserPoolDomain;

  constructor(scope: constructs.Construct, id: string, props: CognitoAuthInfrastructureProps) {
    super(scope, id);

    const region = core.Stack.of(this).region;
    const account = core.Stack.of(this).account;

    const pool = new CognitoCustomerPool(this, 'Pool', {
      userPoolName: `${props.appSpec.name}-user-pool`,
      cognitoDomainPrefix: props.cognitoDomainPrefix,
      selfSignUpEnabled: false,
      mfa: cognito.Mfa.REQUIRED,
      mfaSecondFactor: { otp: true, sms: false },
      groups: props.appSpec.groups,
      appClients: [{
        key: 'default',
        callbackUrls: [`https://${props.zoneName}/oauth2/callback`],
        logoutUrls: [`https://${props.zoneName}`],
        supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
      }],
      removalPolicy: props.removalPolicy,
    });

    const backend = new CognitoSessionBackend(this, 'Backend', {
      ssmParamPrefix: props.ssmParamPrefix,
      domainName: props.zoneName,
      userPoolId: pool.userPool.userPoolId,
      clientId: pool.userPoolClient.userPoolClientId,
      cognitoDomain: pool.cognitoDomainUrl,
      cognitoRegion: region,
      tableRegion: region,
      tableName: `auth-security-${props.zoneName}`,
      // Preserve the original fixed audit resource names for backward compatibility.
      auditBucketName: `auth-audit-logs-cognito-${account}-${region}`,
      auditDatabaseName: 'auth_audit_logs_cognito',
      securityAlertsTopicArn: props.securityAlertsTopicArn,
      sessionRevocationTopicArn: props.sessionRevocationTopicArn,
      autoRevokeOnReuse: props.autoRevokeOnReuse,
      jwtClaimsWhitelist: props.jwtClaimsWhitelist,
      hmacSecretRotationSchedule: props.hmacSecretRotationSchedule,
      auditLogRetentionDays: props.auditLogRetentionDays,
      auditArchiveRetentionDays: props.auditArchiveRetentionDays,
      removalPolicy: props.removalPolicy,
    });

    this.userPool = pool.userPool;
    this.userPoolClient = pool.userPoolClient;
    this.cognitoDomain = pool.userPoolDomain;
    this.configSecretArn = backend.configSecretArn;
    this.kmsKeyArn = backend.kmsKeyArn;
    this.authTableArn = backend.authTableArn;
    this.kvsArn = backend.kvsArn;
  }
}
