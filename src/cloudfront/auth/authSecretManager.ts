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
  readonly securityAlertsTopicArn?: string;
  readonly autoRevokeOnReuse?: boolean;
  readonly jwtClaimsWhitelist?: string[];
}

export class AuthSecretManager extends constructs.Construct {
  public readonly kmsKey: kms.Key;
  public readonly configSecret: secretsmanager.Secret;
  public readonly kvs: cloudfront.KeyValueStore;

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
      'oid', 'tid', 'sub', 'email', 'name', 'preferred_username', 'groups', 'roles',
    ];

    const configSecretName = `cloudfront-auth-config-${props.domainName}`;
    this.configSecret = new secretsmanager.Secret(this, 'ConfigSecret', {
      secretName: configSecretName,
      encryptionKey: this.kmsKey,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          azure_tenant_id: props.azureTenantId,
          azure_client_id: props.azureClientId,
          redirect_uri: `https://${props.domainName}/oauth2/callback`,
          sts_audience: props.stsAudience,
          dynamodb_table_name: props.tableName,
          dynamodb_region: props.tableRegion,
          security_alerts_topic_arn: props.securityAlertsTopicArn || '',
          auto_revoke_on_reuse: props.autoRevokeOnReuse ? 'true' : 'false',
          jwt_claims_whitelist: JSON.stringify(jwtClaimsWhitelist),
          allowed_domains: JSON.stringify([props.domainName]),
          cookie_domain: props.cookieDomain || '',
        }),
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
