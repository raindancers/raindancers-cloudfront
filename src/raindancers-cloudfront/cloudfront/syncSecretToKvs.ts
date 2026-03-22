import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_secretsmanager as secretsmanager,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_logs as logs,
  custom_resources as cr,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface SyncSecretToKvsProps {
  readonly keyValueStore: cloudfront.KeyValueStore;
  readonly secret: secretsmanager.ISecret;
}

export class SyncSecretToKvs extends constructs.Construct {
  constructor(scope: constructs.Construct, id: string, props: SyncSecretToKvsProps) {
    super(scope, id);

    const logGroup = new logs.LogGroup(this, 'SyncFunctionLogGroup', {
      retention: logs.RetentionDays.ONE_WEEK,
    });

    const syncFunction = new lambda.SingletonFunction(this, 'SyncFunction', {
      uuid: 'sync-secret-to-kvs',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/sync-kvs-secret'), {
        bundling: {
          image: lambda.Runtime.PYTHON_3_12.bundlingImage,
          command: [
            'bash', '-c',
            'pip install -r requirements.txt -t /asset-output && cp -au . /asset-output',
          ],
        },
      }),
      timeout: core.Duration.minutes(5),
      logGroup: logGroup,
    });

    syncFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [props.secret.secretArn],
    }));

    syncFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'cloudfront-keyvaluestore:PutKey',
        'cloudfront-keyvaluestore:DeleteKey',
        'cloudfront-keyvaluestore:DescribeKeyValueStore',
      ],
      resources: [props.keyValueStore.keyValueStoreArn],
    }));

    const provider = new cr.Provider(this, 'Provider', {
      onEventHandler: syncFunction,
    });

    new core.CustomResource(this, 'Resource', {
      resourceType: 'Custom::SyncSecretToKvs',
      serviceToken: provider.serviceToken,
      properties: {
        SecretArn: props.secret.secretArn,
        KeyValueStoreArn: props.keyValueStore.keyValueStoreArn,
      },
    });
  }
}
