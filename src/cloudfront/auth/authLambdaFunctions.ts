import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_lambda as lambda,
  aws_iam as iam,
  aws_secretsmanager as secretsmanager,
  aws_kms as kms,
  aws_logs as logs,
  aws_events as events,
  aws_events_targets as targets,
  aws_lambda_event_sources as lambda_event_sources,
  aws_sns as sns,
  aws_sns_subscriptions as sns_subscriptions,
  aws_dynamodb as dynamodb,
  CustomResource,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface AuthLambdaFunctionsProps {
  readonly configSecret: secretsmanager.Secret;
  readonly kmsKey: kms.Key;
  readonly kvs: cloudfront.KeyValueStore;
  readonly authTable: dynamodb.ITable;
  readonly rotationSchedule?: core.Duration;
  readonly sessionRevocationTopicArn?: string;
  readonly logRetentionDays: number;
}

export class AuthLambdaFunctions extends constructs.Construct {
  public readonly copySecretLambda: lambda.Function;
  public readonly rotateSecretLambda: lambda.Function;
  public readonly streamProcessorLambda: lambda.Function;
  public readonly sessionRevocationLambda?: lambda.Function;
  public readonly logGroups: logs.LogGroup[];

  constructor(scope: constructs.Construct, id: string, props: AuthLambdaFunctionsProps) {
    super(scope, id);

    this.logGroups = [];

    const copySecretLogGroup = new logs.LogGroup(this, 'CopySecretLogGroup', {
      retention: props.logRetentionDays as logs.RetentionDays,
      encryptionKey: props.kmsKey,
    });
    this.logGroups.push(copySecretLogGroup);

    this.copySecretLambda = new lambda.Function(this, 'CopySecretToKVS', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      timeout: core.Duration.seconds(30),
      logGroup: copySecretLogGroup,
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/hmacSecret'), {
        bundling: {
          image: lambda.Runtime.PYTHON_3_12.bundlingImage,
          command: [
            'bash', '-c',
            'pip install -r requirements.txt -t /asset-output && cp -au . /asset-output',
          ],
        },
      }),
    });

    props.configSecret.grantRead(this.copySecretLambda);
    props.kmsKey.grantDecrypt(this.copySecretLambda);
    this.copySecretLambda.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cloudfront-keyvaluestore:PutKey', 'cloudfront-keyvaluestore:DescribeKeyValueStore'],
      resources: [props.kvs.keyValueStoreArn],
    }));

    const secretCopyResource = new CustomResource(this, 'SecretCopyResource', {
      serviceToken: this.copySecretLambda.functionArn,
      properties: {
        SecretArn: props.configSecret.secretArn,
        KvsArn: props.kvs.keyValueStoreArn,
      },
    });

    secretCopyResource.node.addDependency(props.kvs);
    secretCopyResource.node.addDependency(props.configSecret);

    const rotateSecretLogGroup = new logs.LogGroup(this, 'RotateSecretLogGroup', {
      retention: props.logRetentionDays as logs.RetentionDays,
      encryptionKey: props.kmsKey,
    });
    this.logGroups.push(rotateSecretLogGroup);

    const rotationSchedule = props.rotationSchedule ?? core.Duration.hours(6);

    this.rotateSecretLambda = new lambda.Function(this, 'RotateSecret', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      timeout: core.Duration.seconds(30),
      logGroup: rotateSecretLogGroup,
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/rotateSecret')),
      environment: {
        SECRET_ARN: props.configSecret.secretArn,
        COPY_LAMBDA_ARN: this.copySecretLambda.functionArn,
        KVS_ARN: props.kvs.keyValueStoreArn,
      },
    });

    props.configSecret.grantRead(this.rotateSecretLambda);
    props.configSecret.grantWrite(this.rotateSecretLambda);
    props.kmsKey.grantEncryptDecrypt(this.rotateSecretLambda);
    this.copySecretLambda.grantInvoke(this.rotateSecretLambda);

    new events.Rule(this, 'RotationSchedule', {
      schedule: events.Schedule.rate(rotationSchedule),
      targets: [new targets.LambdaFunction(this.rotateSecretLambda)],
    });

    const streamProcessorLogGroup = new logs.LogGroup(this, 'StreamProcessorLogGroup', {
      retention: props.logRetentionDays as logs.RetentionDays,
      encryptionKey: props.kmsKey,
    });
    this.logGroups.push(streamProcessorLogGroup);

    this.streamProcessorLambda = new lambda.Function(this, 'StreamProcessor', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.lambda_handler',
      timeout: core.Duration.seconds(60),
      logGroup: streamProcessorLogGroup,
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/stream-processor')),
      environment: {
        KVS_ARN: props.kvs.keyValueStoreArn,
      },
    });

    this.streamProcessorLambda.addEventSource(new lambda_event_sources.DynamoEventSource(props.authTable, {
      startingPosition: lambda.StartingPosition.LATEST,
      batchSize: 100,
      retryAttempts: 3,
    }));

    this.streamProcessorLambda.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cloudfront-keyvaluestore:DeleteKey', 'cloudfront-keyvaluestore:DescribeKeyValueStore'],
      resources: [props.kvs.keyValueStoreArn],
    }));

    if (props.sessionRevocationTopicArn) {
      const sessionRevocationLogGroup = new logs.LogGroup(this, 'SessionRevocationLogGroup', {
        retention: props.logRetentionDays as logs.RetentionDays,
        encryptionKey: props.kmsKey,
      });
      this.logGroups.push(sessionRevocationLogGroup);

      this.sessionRevocationLambda = new lambda.Function(this, 'SessionRevocation', {
        runtime: lambda.Runtime.PYTHON_3_12,
        handler: 'index.lambda_handler',
        timeout: core.Duration.seconds(60),
        logGroup: sessionRevocationLogGroup,
        code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/session-revocation')),
        environment: {
          TABLE_NAME: props.authTable.tableName,
          KVS_ARN: props.kvs.keyValueStoreArn,
        },
      });

      props.authTable.grantReadWriteData(this.sessionRevocationLambda);
      this.sessionRevocationLambda.addToRolePolicy(new iam.PolicyStatement({
        actions: ['cloudfront-keyvaluestore:PutKey', 'cloudfront-keyvaluestore:DescribeKeyValueStore'],
        resources: [props.kvs.keyValueStoreArn],
      }));

      const revocationTopic = sns.Topic.fromTopicArn(this, 'RevocationTopic', props.sessionRevocationTopicArn);
      revocationTopic.addSubscription(new sns_subscriptions.LambdaSubscription(this.sessionRevocationLambda));
    }
  }
}
