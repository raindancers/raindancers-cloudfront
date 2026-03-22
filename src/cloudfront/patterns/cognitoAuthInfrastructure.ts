import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cognito as cognito,
  aws_lambda as lambda,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';
import { AuthLambdaFunctions } from '../auth/authLambdaFunctions';
import { CognitoAuthSecretManager } from '../auth/cognitoAuthSecretManager';
import { AuthSecurityTable } from '../authSecurityTable';
import { AuditLogArchive } from '../logging/auditLogArchive';
import { SsmCrossRegionWriter } from '../ssmCrossRegionWriter';
import { AppSpec } from './authInfrastructure';

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

    const preTokenLambda = new lambda.Function(this, 'PreTokenLambda', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../cloudfront/lambda/pre-token')),
      timeout: core.Duration.seconds(5),
    });

    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: `${props.appSpec.name}-user-pool`,
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      mfa: cognito.Mfa.REQUIRED,
      mfaSecondFactor: { otp: true, sms: false },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      removalPolicy: props.removalPolicy ?? core.RemovalPolicy.RETAIN,
    });

    this.userPool.addTrigger(cognito.UserPoolOperation.PRE_TOKEN_GENERATION_CONFIG, preTokenLambda, cognito.LambdaVersion.V2_0);

    if (props.appSpec.groups) {
      for (const group of props.appSpec.groups) {
        new cognito.CfnUserPoolGroup(this, `Group${group}`, {
          userPoolId: this.userPool.userPoolId,
          groupName: group,
        });
      }
    }

    this.userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
      userPool: this.userPool,
      generateSecret: false,
      authFlows: { userSrp: true },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
        ],
        callbackUrls: [`https://${props.zoneName}/oauth2/callback`],
        logoutUrls: [`https://${props.zoneName}`],
      },
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
    });

    this.cognitoDomain = this.userPool.addDomain('CognitoDomain', {
      cognitoDomain: { domainPrefix: props.cognitoDomainPrefix },
    });

    const authSecurityTable = new AuthSecurityTable(this, 'AuthSecurityTable', {
      tableName: `auth-security-${props.zoneName}`,
      removalPolicy: props.removalPolicy ?? core.RemovalPolicy.RETAIN,
    });

    const cognitoRegion = core.Stack.of(this).region;
    const cognitoDomainUrl = `${props.cognitoDomainPrefix}.auth.${cognitoRegion}.amazoncognito.com`;

    const secretManager = new CognitoAuthSecretManager(this, 'SecretManager', {
      domainName: props.zoneName,
      tableName: authSecurityTable.table.tableName,
      tableRegion: cognitoRegion,
      userPoolId: this.userPool.userPoolId,
      clientId: this.userPoolClient.userPoolClientId,
      cognitoDomain: cognitoDomainUrl,
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
      bucketName: `auth-audit-logs-cognito-${core.Stack.of(this).account}-${core.Stack.of(this).region}`,
      databaseName: 'auth_audit_logs_cognito',
      removalPolicy: props.removalPolicy ?? core.RemovalPolicy.RETAIN,
    });

    const prefix = props.ssmParamPrefix ?? `/auth/${props.zoneName}`;

    new SsmCrossRegionWriter(this, 'SsmWriter', {
      prefix: prefix,
      region: 'us-east-1',
      params: {
        configSecretArn: secretManager.configSecret.secretArn,
        kmsKeyArn: secretManager.kmsKey.keyArn,
        authTableArn: authSecurityTable.table.tableArn,
        kvsArn: secretManager.kvs.keyValueStoreArn,
        cognitoDomain: cognitoDomainUrl,
        clientId: this.userPoolClient.userPoolClientId,
        userPoolId: this.userPool.userPoolId,
      },
    });

    this.configSecretArn = secretManager.configSecret.secretArn;
    this.kmsKeyArn = secretManager.kmsKey.keyArn;
    this.authTableArn = authSecurityTable.table.tableArn;
    this.kvsArn = secretManager.kvs.keyValueStoreArn;
  }
}
