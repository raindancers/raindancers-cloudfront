import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_iam as iam,
  aws_lambda as lambda,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface SsmCrossRegionWriterProps {
  readonly prefix: string;
  readonly region: string;
  readonly params: Record<string, string>;
}

export class SsmCrossRegionWriter extends constructs.Construct {
  constructor(scope: constructs.Construct, id: string, props: SsmCrossRegionWriterProps) {
    super(scope, id);

    const fn = new lambda.Function(this, 'Fn', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      timeout: core.Duration.seconds(30),
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda/ssm-writer')),
    });

    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ssm:PutParameter', 'ssm:DeleteParameters'],
      resources: [`arn:aws:ssm:${props.region}:${core.Aws.ACCOUNT_ID}:parameter${props.prefix}/*`],
    }));

    new core.CustomResource(this, 'Resource', {
      serviceToken: fn.functionArn,
      properties: {
        Prefix: props.prefix,
        Region: props.region,
        Params: core.Fn.toJsonString(props.params),
      },
    });
  }
}
