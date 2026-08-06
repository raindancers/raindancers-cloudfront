import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_iam as iam,
  aws_lambda as lambda,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface AliasTarget {
  readonly dnsName: string;
  readonly hostedZoneId: string;
  readonly evaluateTargetHealth?: boolean;
}

export interface CrossAccountRoute53RecordProps {
  readonly hostedZoneId: string;
  readonly roleArn: string;
  readonly recordName: string;
  readonly recordType: string;
  readonly aliasTarget?: AliasTarget;
  readonly resourceRecords?: string[];
  readonly ttl?: core.Duration;
}

export class CrossAccountRoute53Record extends constructs.Construct {

  private static readonly SINGLETON_KEY = 'CrossAccountRoute53RecordFunction';

  constructor(scope: constructs.Construct, id: string, props: CrossAccountRoute53RecordProps) {
    super(scope, id);

    if (!props.aliasTarget && !props.resourceRecords) {
      throw new Error('Either aliasTarget or resourceRecords must be provided');
    }

    const fn = this.getOrCreateFunction(props.roleArn);

    const resourceProperties: Record<string, unknown> = {
      HostedZoneId: props.hostedZoneId,
      RoleArn: props.roleArn,
      RecordName: props.recordName,
      RecordType: props.recordType,
    };

    if (props.aliasTarget) {
      resourceProperties.AliasTarget = {
        DNSName: props.aliasTarget.dnsName,
        HostedZoneId: props.aliasTarget.hostedZoneId,
        EvaluateTargetHealth: props.aliasTarget.evaluateTargetHealth === true ? 'true' : 'false',
      };
    }

    if (props.resourceRecords) {
      resourceProperties.ResourceRecords = props.resourceRecords;
    }

    if (props.ttl) {
      resourceProperties.TTL = props.ttl.toSeconds().toString();
    }

    new core.CustomResource(this, 'Resource', {
      serviceToken: fn.functionArn,
      properties: resourceProperties,
    });
  }

  private getOrCreateFunction(roleArn: string): lambda.Function {
    const stack = core.Stack.of(this);
    const existing = stack.node.tryFindChild(CrossAccountRoute53Record.SINGLETON_KEY);

    if (existing) {
      const fn = existing as lambda.Function;
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: ['sts:AssumeRole'],
        resources: [roleArn],
      }));
      return fn;
    }

    const fn = new lambda.Function(stack, CrossAccountRoute53Record.SINGLETON_KEY, {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      timeout: core.Duration.seconds(30),
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda/cross-account-dns-record')),
    });

    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['sts:AssumeRole'],
      resources: [roleArn],
    }));

    return fn;
  }
}
