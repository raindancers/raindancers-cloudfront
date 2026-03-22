import * as core from 'aws-cdk-lib';
import {
  aws_dynamodb as dynamodb,
  RemovalPolicy,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface AuthSecurityTableProps {
  readonly tableName?: string;
  readonly removalPolicy?: RemovalPolicy;
}

export class AuthSecurityTable extends constructs.Construct {
  public readonly table: dynamodb.ITable;

  constructor(scope: constructs.Construct, id: string, props?: AuthSecurityTableProps) {
    super(scope, id);

    const table = new dynamodb.Table(this, 'Table', {
      tableName: props?.tableName,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expiresAt',
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      removalPolicy: props?.removalPolicy ?? RemovalPolicy.RETAIN,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
    });

    table.addGlobalSecondaryIndex({
      indexName: 'GSI1',
      partitionKey: { name: 'gsi1pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'gsi1sk', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    table.addGlobalSecondaryIndex({
      indexName: 'GSI2',
      partitionKey: { name: 'gsi2pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'gsi2sk', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    this.table = table;

    new core.CfnOutput(this, 'TableName', {
      value: this.table.tableName,
      description: 'Auth Security DynamoDB Table Name',
    });

    new core.CfnOutput(this, 'TableArn', {
      value: this.table.tableArn,
      description: 'Auth Security DynamoDB Table ARN',
    });
  }
}
