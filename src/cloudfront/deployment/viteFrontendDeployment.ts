import * as core from 'aws-cdk-lib';
import { aws_s3 as s3, aws_s3_deployment as s3deploy, aws_cloudfront as cloudfront } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface ViteFrontendDeploymentProps {
  readonly appName: string;
  readonly sourcePath: string;
  readonly destinationBucket: s3.IBucket;
  readonly distribution: cloudfront.IDistribution;
}

export class ViteFrontendDeployment extends Construct {
  public readonly deployment: s3deploy.BucketDeployment;

  constructor(scope: Construct, id: string, props: ViteFrontendDeploymentProps) {
    super(scope, id);

    this.deployment = new s3deploy.BucketDeployment(this, 'Deployment', {
      sources: [
        s3deploy.Source.asset(props.sourcePath, {
          bundling: {
            image: core.DockerImage.fromRegistry('node:20-alpine'),
            command: [
              'sh', '-c',
              'npm ci --include=dev && npm run build && cp -r dist/. /asset-output/',
            ],
          },
        }),
      ],
      destinationBucket: props.destinationBucket,
      destinationKeyPrefix: `${props.appName}/`,
      distribution: props.distribution,
      distributionPaths: ['/*'],
    });
  }
}
