import * as core from 'aws-cdk-lib';
import {
  aws_s3 as s3,
  aws_kms as kms,
  aws_logs as logs,
  aws_kinesisfirehose as firehose,
  aws_glue as glue,
  aws_iam as iam,
  RemovalPolicy,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface AuditLogArchiveProps {
  readonly logGroupNames: string[];
  readonly kmsKey: kms.IKey;
  readonly retentionDays?: number;
  readonly archiveRetentionDays?: number;
  readonly bucketName?: string;
  readonly databaseName?: string;
  readonly removalPolicy?: RemovalPolicy;
}

export class AuditLogArchive extends constructs.Construct {
  public readonly bucket: s3.Bucket;
  public readonly database: glue.CfnDatabase;
  public readonly table: glue.CfnTable;
  public readonly deliveryStream: firehose.CfnDeliveryStream;

  constructor(scope: constructs.Construct, id: string, props: AuditLogArchiveProps) {
    super(scope, id);

    const retentionDays = props.retentionDays ?? 30;
    const archiveRetentionDays = props.archiveRetentionDays ?? 365;
    const databaseName = props.databaseName ?? 'audit_logs';
    const tableName = 'logs';

    // Create S3 bucket for audit log archive
    this.bucket = new s3.Bucket(this, 'Bucket', {
      bucketName: props.bucketName ?? `audit-logs-${core.Stack.of(this).account}-${core.Stack.of(this).region}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      intelligentTieringConfigurations: [{
        name: 'archive-tiering',
        archiveAccessTierTime: core.Duration.days(90),
        deepArchiveAccessTierTime: core.Duration.days(180),
      }],
      lifecycleRules: [{
        id: 'delete-old-logs',
        enabled: true,
        expiration: core.Duration.days(archiveRetentionDays),
      }],
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
      autoDeleteObjects: props.removalPolicy === RemovalPolicy.DESTROY,
    });

    // Create Glue database
    this.database = new glue.CfnDatabase(this, 'Database', {
      catalogId: core.Stack.of(this).account,
      databaseInput: {
        name: databaseName,
        description: 'Audit logs database for Athena queries',
      },
    });

    // Create Glue table for Parquet schema
    this.table = new glue.CfnTable(this, 'Table', {
      catalogId: core.Stack.of(this).account,
      databaseName: this.database.ref,
      tableInput: {
        name: tableName,
        description: 'Audit logs in Parquet format',
        storageDescriptor: {
          columns: [
            { name: 'timestamp', type: 'bigint', comment: 'Log timestamp in milliseconds' },
            { name: 'message', type: 'string', comment: 'Log message' },
            { name: 'log_group', type: 'string', comment: 'CloudWatch log group name' },
            { name: 'log_stream', type: 'string', comment: 'CloudWatch log stream name' },
            { name: 'event_type', type: 'string', comment: 'Event type (extracted from message)' },
            { name: 'user_id', type: 'string', comment: 'User identifier (if available)' },
            { name: 'ip_address', type: 'string', comment: 'Client IP address (if available)' },
          ],
          location: `s3://${this.bucket.bucketName}/logs/`,
          inputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
          serdeInfo: {
            serializationLibrary: 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe',
            parameters: {
              'serialization.format': '1',
            },
          },
        },
        partitionKeys: [
          { name: 'year', type: 'string' },
          { name: 'month', type: 'string' },
          { name: 'day', type: 'string' },
        ],
        tableType: 'EXTERNAL_TABLE',
      },
    });

    // Create IAM role for Firehose
    const firehoseRole = new iam.Role(this, 'FirehoseRole', {
      assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com'),
    });

    this.bucket.grantWrite(firehoseRole);
    props.kmsKey.grantEncryptDecrypt(firehoseRole);

    firehoseRole.addToPolicy(new iam.PolicyStatement({
      actions: ['glue:GetTable', 'glue:GetTableVersion', 'glue:GetTableVersions'],
      resources: [
        `arn:aws:glue:${core.Stack.of(this).region}:${core.Stack.of(this).account}:catalog`,
        `arn:aws:glue:${core.Stack.of(this).region}:${core.Stack.of(this).account}:database/${databaseName}`,
        `arn:aws:glue:${core.Stack.of(this).region}:${core.Stack.of(this).account}:table/${databaseName}/${tableName}`,
      ],
    }));

    // Create Kinesis Firehose delivery stream with Parquet conversion
    this.deliveryStream = new firehose.CfnDeliveryStream(this, 'DeliveryStream', {
      deliveryStreamType: 'DirectPut',
      extendedS3DestinationConfiguration: {
        bucketArn: this.bucket.bucketArn,
        roleArn: firehoseRole.roleArn,
        prefix: 'logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/',
        errorOutputPrefix: 'errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/',
        bufferingHints: {
          intervalInSeconds: 300,
          sizeInMBs: 128,
        },
        compressionFormat: 'UNCOMPRESSED',
        dataFormatConversionConfiguration: {
          enabled: true,
          schemaConfiguration: {
            roleArn: firehoseRole.roleArn,
            databaseName: this.database.ref,
            tableName: this.table.ref,
            region: core.Stack.of(this).region,
            versionId: 'LATEST',
          },
          inputFormatConfiguration: {
            deserializer: {
              openXJsonSerDe: {},
            },
          },
          outputFormatConfiguration: {
            serializer: {
              parquetSerDe: {
                compression: 'SNAPPY',
              },
            },
          },
        },
      },
    });

    this.deliveryStream.addDependency(this.database);
    this.deliveryStream.addDependency(this.table);
    this.deliveryStream.node.addDependency(firehoseRole);

    // Create IAM role for CloudWatch Logs subscription
    const logsRole = new iam.Role(this, 'LogsRole', {
      assumedBy: new iam.ServicePrincipal('logs.amazonaws.com'),
      inlinePolicies: {
        FirehosePermissions: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['firehose:PutRecord'],
              resources: [this.deliveryStream.attrArn],
            }),
          ],
        }),
      },
    });

    // Create subscription filters for each log group
    props.logGroupNames.forEach((logGroupName, index) => {
      new logs.CfnSubscriptionFilter(this, `Subscription${index}`, {
        logGroupName: logGroupName,
        filterPattern: '',
        destinationArn: this.deliveryStream.attrArn,
        roleArn: logsRole.roleArn,
      });
    });

    // Outputs
    new core.CfnOutput(this, 'BucketName', {
      value: this.bucket.bucketName,
      description: 'S3 Bucket for Audit Log Archive',
    });

    new core.CfnOutput(this, 'DatabaseName', {
      value: this.database.ref,
      description: 'Glue Database Name for Athena Queries',
    });

    new core.CfnOutput(this, 'TableName', {
      value: this.table.ref,
      description: 'Glue Table Name for Athena Queries',
    });

    new core.CfnOutput(this, 'DeliveryStreamArn', {
      value: this.deliveryStream.attrArn,
      description: 'Kinesis Firehose Delivery Stream ARN',
    });
  }
}
