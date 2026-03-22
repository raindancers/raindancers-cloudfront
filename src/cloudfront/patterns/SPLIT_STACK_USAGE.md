# Split-Stack CloudFront Auth Architecture

## Overview

This architecture splits CloudFront authentication resources across two regions:
- **Regional Stack (ap-southeast-2)**: DynamoDB, Secrets Manager, KMS, Lambda functions, audit logging
- **CloudFront Stack (us-east-1)**: CloudFront Distribution, Lambda@Edge, CloudFront Functions, ACM Certificate

## Benefits

- Lower latency for ANZ traffic (DynamoDB in ap-southeast-2)
- Reduced us-east-1 footprint
- Better data locality
- Regional Lambda functions closer to data

## Usage Example

```typescript
import * as core from 'aws-cdk-lib';
import { aws_s3 as s3, aws_cloudfront_origins as origins } from 'aws-cdk-lib';
import * as local from '../constructs';

// Regional Stack (ap-southeast-2)
export class AuthRegionalStack extends core.Stack {
  public readonly authInfra: local.cloudfront.patterns.AuthInfrastructure;

  constructor(scope: core.App, id: string, props: core.StackProps) {
    super(scope, id, props);

    this.authInfra = new local.cloudfront.patterns.AuthInfrastructure(this, 'AuthInfra', {
      domainNames: ['bicep-cdk.raindancers.cloud'],
      redirectUri: 'https://bicep-cdk.raindancers.cloud/oauth2/callback',
      hmacSecretRotationSchedule: core.Duration.hours(12),
      autoRevokeOnReuse: true,
      auditLogRetentionDays: 30,
      auditArchiveRetentionDays: 365,
    });
  }
}

// CloudFront Stack (us-east-1)
export class CloudFrontStack extends core.Stack {
  constructor(
    scope: core.App,
    id: string,
    props: core.StackProps & { 
      regionalInfra: local.cloudfront.patterns.AuthInfrastructure;
      jwtDecoderUrl: string;
    }
  ) {
    super(scope, id, { ...props, crossRegionReferences: true });

    const zone = new local.route53.PublicHostedZone(this, 'Zone', {
      zoneName: 'bicep-cdk.raindancers.cloud',
    });

    const cert = new local.cloudfront.CloudFrontCertificate(this, 'Certificate', {
      domainName: 'bicep-cdk.raindancers.cloud',
      hostedZone: zone,
    });

    const webAcl = new local.cloudfront.CloudFrontWebAcl(this, 'WebAcl', {
      rateLimit: 10000,
      enableManagedRules: true,
      allowedCountries: ['NewZealand', 'Australia'],
    });

    const bucket = new s3.Bucket(this, 'ContentBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    });

    const authDistribution = new local.cloudfront.patterns.CloudFrontWithAzureAuthSplit(
      this,
      'AuthDistribution',
      {
        origin: origins.S3BucketOrigin.withOriginAccessControl(bucket),
        domainNames: ['bicep-cdk.raindancers.cloud'],
        certificate: cert.certificate,
        webAclId: webAcl.webAclArn,
        jwtDecoderUrl: props.jwtDecoderUrl,
        regionalInfrastructure: props.regionalInfra,
      }
    );

    new local.route53.CloudFrontAliasRecords(this, 'AliasRecords', {
      zone: zone,
      distribution: authDistribution.distribution,
    });
  }
}

// App
const app = new core.App();

const regionalStack = new AuthRegionalStack(app, 'AuthRegional', {
  env: { region: 'ap-southeast-2', account: process.env.CDK_DEFAULT_ACCOUNT },
});

const cloudFrontStack = new CloudFrontStack(app, 'CloudFront', {
  env: { region: 'us-east-1', account: process.env.CDK_DEFAULT_ACCOUNT },
  crossRegionReferences: true,
  regionalInfra: regionalStack.authInfra,
  jwtDecoderUrl: 'https://example.com/jwt',
});

cloudFrontStack.addDependency(regionalStack);
```

## Migration from Single Stack

If you're currently using `CloudFrontWithAzureAuth`:

1. Create new regional stack with `AuthInfrastructure`
2. Create new CloudFront stack with `CloudFrontWithAzureAuthSplit`
3. Deploy regional stack first
4. Deploy CloudFront stack
5. Update DNS
6. Delete old single-stack resources

## Resource Locations

### ap-southeast-2
- DynamoDB Table
- Secrets Manager Secret
- KMS Key
- Lambda Functions (copy, rotate, stream processor, revocation)
- CloudWatch Log Groups
- S3 Audit Archive Bucket
- IAM Role (created here, used in us-east-1)

### us-east-1
- CloudFront Distribution
- CloudFront Function
- Lambda@Edge Function
- CloudFront KeyValueStore
- ACM Certificate
- WAF WebACL
