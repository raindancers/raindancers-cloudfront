import * as core from 'aws-cdk-lib';
import * as constructs from 'constructs';
import { AuthLambdaFunctions } from '../auth/authLambdaFunctions';
import { CognitoAuthSecretManager } from '../auth/cognitoAuthSecretManager';
import { AuthSecurityTable } from '../authSecurityTable';
import { AuditLogArchive } from '../logging/auditLogArchive';
import { SsmCrossRegionWriter } from '../ssmCrossRegionWriter';

/**
 * Props for {@link CognitoSessionBackend}. Generic — no project specifics baked
 * in. Pool identifiers are passed in (from {@link CognitoCustomerPool} or any
 * externally-managed pool), so this construct is agnostic to how the pool was
 * created.
 */
export interface CognitoSessionBackendProps {
  /** SSM prefix to publish identifiers under. @default `/auth/${domainName}` */
  readonly ssmParamPrefix?: string;
  /** Canonical domain — used for the config-secret name and default resource names. */
  readonly domainName: string;
  /**
   * Config-secret name (the secret the edge Lambdas fetch by name). Override to
   * decouple the name from {@link domainName}, e.g. to avoid a physical-name
   * collision when replacing an existing auth construct in the same stack.
   * @default `cloudfront-auth-config-${domainName}`
   */
  readonly configSecretName?: string;
  /** Cognito user pool id. */
  readonly userPoolId: string;
  /** Cognito app client id embedded in the config secret. */
  readonly clientId: string;
  /** Hosted-UI Cognito domain URL. */
  readonly cognitoDomain: string;
  /** Region of the Cognito pool. @default this stack's region */
  readonly cognitoRegion?: string;
  /** Region the auth table lives in. @default this stack's region */
  readonly tableRegion?: string;
  /** Auth-security DynamoDB table name. @default `auth-security-${domainName}` */
  readonly tableName?: string;
  /** Audit log S3 bucket name. @default derived from {@link domainName}. */
  readonly auditBucketName?: string;
  /** Audit log Glue database name. @default derived from {@link domainName}. */
  readonly auditDatabaseName?: string;
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
 * The session substrate for the custom-UI / hosted-UI Cognito auth flows:
 * the HMAC KMS signing key, the auth-security DynamoDB table
 * (`STATE#`/`SESSION#`/`REFRESH#`), the CloudFront KeyValueStore (holds
 * `jwt.secret` and the `revoked:` denylist), the config secret consumed by the
 * edge Lambdas, secret rotation + session-revocation wiring, and the audit-log
 * archive. Publishes all identifiers under an SSM prefix for the edge/CDN
 * construct to read.
 *
 * Generic and reusable: it takes Cognito pool identifiers as props and knows
 * nothing about any specific project.
 */
export class CognitoSessionBackend extends constructs.Construct {
  public readonly configSecretArn: string;
  public readonly kmsKeyArn: string;
  public readonly authTableArn: string;
  public readonly kvsArn: string;
  public readonly ssmParamPrefix: string;

  constructor(scope: constructs.Construct, id: string, props: CognitoSessionBackendProps) {
    super(scope, id);

    const region = core.Stack.of(this).region;
    const account = core.Stack.of(this).account;
    const cognitoRegion = props.cognitoRegion ?? region;
    const tableRegion = props.tableRegion ?? region;
    const sanitized = props.domainName.toLowerCase().replace(/[^a-z0-9-]/g, '-');

    const authSecurityTable = new AuthSecurityTable(this, 'AuthSecurityTable', {
      tableName: props.tableName ?? `auth-security-${props.domainName}`,
      removalPolicy: props.removalPolicy ?? core.RemovalPolicy.RETAIN,
    });

    const secretManager = new CognitoAuthSecretManager(this, 'SecretManager', {
      domainName: props.domainName,
      configSecretName: props.configSecretName,
      tableName: authSecurityTable.table.tableName,
      tableRegion: tableRegion,
      userPoolId: props.userPoolId,
      clientId: props.clientId,
      cognitoDomain: props.cognitoDomain,
      cognitoRegion: cognitoRegion,
      securityAlertsTopicArn: props.securityAlertsTopicArn,
      autoRevokeOnReuse: props.autoRevokeOnReuse,
      jwtClaimsWhitelist: props.jwtClaimsWhitelist,
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
      bucketName: props.auditBucketName ?? `auth-audit-logs-${sanitized}-${account}-${region}`,
      databaseName: props.auditDatabaseName ?? `auth_audit_logs_${sanitized.replace(/-/g, '_')}`,
      removalPolicy: props.removalPolicy ?? core.RemovalPolicy.RETAIN,
    });

    const prefix = props.ssmParamPrefix ?? `/auth/${props.domainName}`;
    this.ssmParamPrefix = prefix;

    new SsmCrossRegionWriter(this, 'SsmWriter', {
      prefix: prefix,
      region: 'us-east-1',
      params: {
        configSecretArn: secretManager.configSecret.secretArn,
        kmsKeyArn: secretManager.kmsKey.keyArn,
        authTableArn: authSecurityTable.table.tableArn,
        kvsArn: secretManager.kvs.keyValueStoreArn,
        cognitoDomain: props.cognitoDomain,
        clientId: props.clientId,
        userPoolId: props.userPoolId,
      },
    });

    this.configSecretArn = secretManager.configSecret.secretArn;
    this.kmsKeyArn = secretManager.kmsKey.keyArn;
    this.authTableArn = authSecurityTable.table.tableArn;
    this.kvsArn = secretManager.kvs.keyValueStoreArn;
  }
}
