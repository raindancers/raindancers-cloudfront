import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_s3 as s3,
} from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { ViewerMtlsAccess, ViewerMtlsAccessProps } from '../src/cloudfront/patterns/viewer-mtls-access';

function makeStack(): core.Stack {
  const app = new core.App();
  return new core.Stack(app, 'TestStack', { env: { account: '111111111111', region: 'eu-west-2' } });
}

function makeDistribution(stack: core.Stack, viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy): cloudfront.Distribution {
  return new cloudfront.Distribution(stack, 'Dist', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('origin.example.com'),
      viewerProtocolPolicy,
    },
  });
}

function makeAccess(stack: core.Stack, overrides?: Partial<ViewerMtlsAccessProps>): ViewerMtlsAccess {
  const bucket = s3.Bucket.fromBucketName(stack, 'CaBucket', 'ca-bundle-bucket');
  return new ViewerMtlsAccess(stack, 'Mtls', {
    trustStore: { caBundleBucket: bucket, caBundleKey: 'ca-bundle.pem' },
    ...overrides,
  });
}

describe('ViewerMtlsAccess — trust store (Task 4)', () => {
  it('Property 9 (4.1) — mutually-exclusive trust-store sources fail synth', () => {
    const stack = makeStack();
    const bucket = s3.Bucket.fromBucketName(stack, 'CaBucket', 'ca-bundle-bucket');
    expect(() =>
      new ViewerMtlsAccess(stack, 'Mtls', {
        trustStore: { caBundleBucket: bucket, caBundleKey: 'ca.pem', existingTrustStoreId: 'ts-123' },
      }),
    ).toThrow(/not both/i);
  });

  it('requires at least one trust-store source', () => {
    const stack = makeStack();
    expect(() => new ViewerMtlsAccess(stack, 'Mtls', { trustStore: {} })).toThrow(/requires either/i);
  });

  it('creates a CfnTrustStore in create mode', () => {
    const stack = makeStack();
    makeAccess(stack);
    Template.fromStack(stack).resourceCountIs('AWS::CloudFront::TrustStore', 1);
  });
});

describe('ViewerMtlsAccess — attachToDistribution wiring & guards (Task 6)', () => {
  it('6.1 — sets viewer mTLS mode and associates the connection function', () => {
    const stack = makeStack();
    const dist = makeDistribution(stack, cloudfront.ViewerProtocolPolicy.HTTPS_ONLY);
    makeAccess(stack).attachToDistribution(dist);
    Template.fromStack(stack).hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        ViewerMtlsConfig: Match.objectLike({
          Mode: 'Required',
          TrustStoreConfig: Match.objectLike({ AdvertiseTrustStoreCaNames: true, IgnoreCertificateExpiry: false }),
        }),
        ConnectionFunctionAssociation: Match.objectLike({ Id: Match.anyValue() }),
      }),
    });
  });

  it('Property 7 (6.2) — no viewer-request function is ever added', () => {
    const stack = makeStack();
    const dist = makeDistribution(stack, cloudfront.ViewerProtocolPolicy.HTTPS_ONLY);
    makeAccess(stack, {
      certPresentSignal: { cookieName: 'fs_internal', cookieAttributes: 'Path=/; Secure' },
    }).attachToDistribution(dist);
    const dc: any = Template.fromStack(stack).findResources('AWS::CloudFront::Distribution');
    const config = Object.values(dc)[0] as any;
    const assocs: any[] = config.Properties.DistributionConfig.DefaultCacheBehavior.FunctionAssociations ?? [];
    for (const a of assocs) {
      expect(a.EventType).not.toBe('viewer-request');
    }
  });

  it('Property 8 (6.3) — HTTPS-only violation fails synth (ALLOW_ALL)', () => {
    const stack = makeStack();
    const dist = makeDistribution(stack, cloudfront.ViewerProtocolPolicy.ALLOW_ALL);
    expect(() => makeAccess(stack).attachToDistribution(dist)).toThrow(/HTTPS-only/i);
  });

  it('Property 8 (6.3) — REDIRECT_TO_HTTPS also fails synth (must be https-only)', () => {
    const stack = makeStack();
    const dist = makeDistribution(stack, cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS);
    expect(() => makeAccess(stack).attachToDistribution(dist)).toThrow(/HTTPS-only/i);
  });

  it('6.4 — viewer-response function present iff certPresentSignal is set', () => {
    // With signal: a viewer-response association is added.
    const stackWith = makeStack();
    const distWith = makeDistribution(stackWith, cloudfront.ViewerProtocolPolicy.HTTPS_ONLY);
    makeAccess(stackWith, {
      certPresentSignal: { cookieName: 'fs_internal', cookieAttributes: 'Path=/; Secure' },
    }).attachToDistribution(distWith);
    const tWith = Template.fromStack(stackWith);
    tWith.resourceCountIs('AWS::CloudFront::Function', 1);
    const withCfg = (Object.values(tWith.findResources('AWS::CloudFront::Distribution'))[0] as any)
      .Properties.DistributionConfig.DefaultCacheBehavior.FunctionAssociations ?? [];
    expect(withCfg.some((a: any) => a.EventType === 'viewer-response')).toBe(true);

    // Without signal: no CloudFront Function resource synthesised.
    const stackNo = makeStack();
    const distNo = makeDistribution(stackNo, cloudfront.ViewerProtocolPolicy.HTTPS_ONLY);
    makeAccess(stackNo).attachToDistribution(distNo);
    Template.fromStack(stackNo).resourceCountIs('AWS::CloudFront::Function', 0);
  });
});
