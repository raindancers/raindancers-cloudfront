import * as core from 'aws-cdk-lib';
import {
  aws_iam as iam,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';
import { AuthSecretManager } from '../auth/auth-secret-manager';
import { AuthLambdaFunctions } from '../auth/auth-lambda-functions';
import { AuthSecurityTable } from '../auth-security-table';
import { AuditLogArchive } from '../logging/audit-log-archive';
import { SsmCrossRegionWriter } from '../ssm-cross-region-writer';

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
  readonly tenantId: string;
  readonly clientId: string;
  readonly oauth2CallbackRoleName: string;
  readonly appSpec: AppSpec;
  readonly securityAlertsTopicArn?: string;
  readonly sessionRevocationTopicArn?: string;
  readonly autoRevokeOnReuse?: boolean;
  readonly jwtClaimsWhitelist?: string[];
  readonly hmacSecretRotationSchedule?: core.Duration;
  readonly auditLogRetentionDays?: number;
  readonly auditArchiveRetentionDays?: number;
  readonly removalPolicy?: core.RemovalPolicy;
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
      tableName: authSecurityTable.table.tableName,
      tableRegion: core.Stack.of(this).region,
      azureTenantId: props.tenantId,
      azureClientId: props.clientId,
      stsAudience: 'api://AzureADTokenExchange',
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
      bucketName: `auth-audit-logs-${core.Stack.of(this).account}-${core.Stack.of(this).region}`,
      databaseName: 'auth_audit_logs',
      removalPolicy: props.removalPolicy ?? core.RemovalPolicy.RETAIN,
    });

    const oidcProvider = new iam.OpenIdConnectProvider(this, 'OidcProvider', {
      url: `https://login.microsoftonline.com/${props.tenantId}/v2.0`,
      clientIds: [props.clientId],
      thumbprints: [AZURE_AD_THUMBPRINT],
    });

    this.configSecretArn = secretManager.configSecret.secretArn;
    this.kmsKeyArn = secretManager.kmsKey.keyArn;
    this.authTableArn = authSecurityTable.table.tableArn;
    this.kvsArn = secretManager.kvs.keyValueStoreArn;
    this.oidcProvider = oidcProvider;

    const prefix = props.ssmParamPrefix ?? `/auth/${props.zoneName}`;

    new SsmCrossRegionWriter(this, 'SsmWriter', {
      prefix: prefix,
      region: 'us-east-1',
      params: {
        configSecretArn: secretManager.configSecret.secretArn,
        kmsKeyArn: secretManager.kmsKey.keyArn,
        authTableArn: authSecurityTable.table.tableArn,
        kvsArn: secretManager.kvs.keyValueStoreArn,
        tenantId: props.tenantId,
        clientId: props.clientId,
        oauth2CallbackRoleName: props.oauth2CallbackRoleName,
      },
    });
  }
}
