import * as path from 'path';
import * as core from 'aws-cdk-lib';
import { aws_lambda as lambda } from 'aws-cdk-lib';
import * as constructs from 'constructs';

export class JwtDecoder extends constructs.Construct {
  public readonly functionUrl: string;

  constructor(scope: constructs.Construct, id: string) {
    super(scope, id);

    const fn = new lambda.Function(this, 'Function', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda/jwt-decoder')),
      timeout: core.Duration.seconds(30),
    });

    const fnUrl = fn.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.NONE,
    });

    this.functionUrl = fnUrl.url;
  }
}
