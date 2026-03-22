import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_secretsmanager as secretsmanager,
  aws_kms as kms,
  aws_iam as iam,
  RemovalPolicy,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface CognitoAuthSecretManagerProps {
  readonly domainName: string;
  readonly tableName: string;
  readonly tableRegion: string;
  readonly userPoolId: string;
  readonly clientId: string;
  readonly cognitoDomain: string;
  readonly cognitoRegion: string;
  readonly securityAlertsTopicArn?: string;
  readonly autoRevokeOnReuse?: boolean;
  readonly jwtClaimsWhitelist?: string[];
}

export class CognitoAuthSecretManager extends constructs.Construct {
  public readonly kmsKey: kms.Key;
  public readonly configSecret: secretsmanager.Secret;
  public readonly kvs: cloudfront.KeyValueStore;

  constructor(scope: constructs.Construct, id: string, props: CognitoAuthSecretManagerProps) {
    super(scope, id);

    this.kmsKey = new kms.Key(this, 'KmsKey', {
      description: 'KMS key for CloudFront Cognito auth secret encryption',
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
      'sub', 'email', 'name', 'cognito:groups', 'roles',
    ];

    this.configSecret = new secretsmanager.Secret(this, 'ConfigSecret', {
      secretName: `cloudfront-auth-config-${props.domainName}`,
      encryptionKey: this.kmsKey,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          idp_type: 'cognito',
          cognito_user_pool_id: props.userPoolId,
          cognito_client_id: props.clientId,
          cognito_domain: props.cognitoDomain,
          cognito_region: props.cognitoRegion,
          redirect_uri: `https://${props.domainName}/oauth2/callback`,
          dynamodb_table_name: props.tableName,
          dynamodb_region: props.tableRegion,
          security_alerts_topic_arn: props.securityAlertsTopicArn ?? '',
          auto_revoke_on_reuse: props.autoRevokeOnReuse ? 'true' : 'false',
          jwt_claims_whitelist: JSON.stringify(jwtClaimsWhitelist),
          allowed_domains: JSON.stringify([props.domainName]),
        }),
        generateStringKey: 'hmac_key',
        excludePunctuation: true,
        passwordLength: 64,
        requireEachIncludedType: false,
      },
      description: 'Configuration and HMAC secret for CloudFront Cognito authentication',
    });

    this.kvs = new cloudfront.KeyValueStore(this, 'AuthKVS', {
      comment: 'HMAC secret and session revocation denylist',
    });
  }
}
