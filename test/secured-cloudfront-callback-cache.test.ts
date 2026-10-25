import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront_origins as origins,
  aws_certificatemanager as acm,
} from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { SecuredCloudFront } from '../src/cloudfront/patterns/securedCloudFront';

/**
 * Regression test for the OAuth callback cache policy.
 *
 * The /oauth2/callback response sets the session cookies (auth_session,
 * azure_token) via Set-Cookie. CloudFront strips Set-Cookie from any cacheable
 * response whose cache policy does not key on those cookies. A cacheable policy
 * on the callback behaviour (even maxTtl=1s) therefore silently drops the auth
 * cookies before they reach the browser, breaking login entirely.
 *
 * The callback behaviour MUST use a non-caching policy (CACHING_DISABLED) so
 * Set-Cookie passes straight through to the viewer.
 */
describe('SecuredCloudFront OAuth callback caching', () => {
  // Managed CachePolicy id for "Managed-CachingDisabled".
  const CACHING_DISABLED_ID = '4135ea2d-6df8-44a3-9df3-4b5a84be39ad';

  // The EdgeFunction asset bundling references pre-bundled Python deps at
  // src/cloudfront/lambda-bundled/* (relative to the lambda source). Those are
  // produced by the compile task into lib/cloudfront/lambda-bundled/*. Link them
  // into src so a from-source synth in this test can bundle the callback Lambda.
  beforeAll(() => {
    const srcBundled = path.join(__dirname, '../src/cloudfront/lambda-bundled');
    const libBundled = path.join(__dirname, '../lib/cloudfront/lambda-bundled');
    if (!fs.existsSync(srcBundled) && fs.existsSync(libBundled)) {
      fs.symlinkSync(libBundled, srcBundled, 'dir');
    }
  });

  function synth(): Template {
    const app = new core.App();
    // EdgeFunction requires an explicit region on the stack.
    const stack = new core.Stack(app, 'TestStack', {
      env: { account: '111111111111', region: 'us-east-1' },
    });

    const certificate = acm.Certificate.fromCertificateArn(
      stack,
      'Cert',
      'arn:aws:acm:us-east-1:111111111111:certificate/00000000-0000-0000-0000-000000000000',
    );

    new SecuredCloudFront(stack, 'Secured', {
      defaultBehavior: {
        origin: new origins.HttpOrigin('origin.example.com'),
      },
      domainNames: ['payload.example.com'],
      certificate: certificate,
      authSsmParamPrefix: '/auth/test',
      authRegion: 'us-east-1',
      enableUserInfoInjection: false,
    });

    return Template.fromStack(stack);
  }

  test('the /oauth2/callback behaviour uses the non-caching (CACHING_DISABLED) policy', () => {
    const template = synth();

    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({
            PathPattern: '/oauth2/callback',
            CachePolicyId: CACHING_DISABLED_ID,
          }),
        ]),
      }),
    });
  });

  test('no cacheable custom cache policy (maxTtl=1) is created for the callback', () => {
    const template = synth();

    // The old buggy default created a custom CachePolicy with MaxTTL: 1, which
    // caused CloudFront to strip Set-Cookie. Guard against its reintroduction.
    const policies = template.findResources('AWS::CloudFront::CachePolicy');
    for (const [, resource] of Object.entries(policies)) {
      const cfg = (resource as any).Properties?.CachePolicyConfig;
      expect(cfg?.MaxTTL).not.toBe(1);
    }
  });

  /**
   * Regression for the RS256 web-identity key-region bug.
   *
   * The mint's generated `config_generated.py` embeds WEB_IDENTITY_KEY_REGION so
   * the Lambda@Edge targets the right region for kms:Sign. An earlier version
   * sourced it from `ssm.StringParameter.valueForStringParameter(...)`, whose
   * value is a DEPLOY-TIME CDK token — it serialized into the Python source as
   * the literal `${Token[...]}`, so the deployed mint did
   * `boto3.client('kms', region_name='${Token[...]}')` and threw at init, which
   * CloudFront surfaced as HTTP 500 "Configuration error" (no Lambda log — it
   * failed before the handler ran). It must be a CONCRETE string: `authRegion`,
   * the region the asymmetric key is created in.
   */
  test('generated mint config embeds a concrete WEB_IDENTITY_KEY_REGION, not a CDK token', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'WiStack', {
      env: { account: '111111111111', region: 'us-east-1' },
    });
    const certificate = acm.Certificate.fromCertificateArn(
      stack,
      'Cert',
      'arn:aws:acm:us-east-1:111111111111:certificate/00000000-0000-0000-0000-000000000000',
    );
    new SecuredCloudFront(stack, 'Secured', {
      defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
      domainNames: ['payload.example.com'],
      certificate: certificate,
      authSsmParamPrefix: '/auth/test',
      authRegion: 'ap-southeast-2',
      enableUserInfoInjection: false,
      enableWebIdentityToken: true,
      webIdentityIssuer: 'https://payload.example.com',
    });

    const assembly = app.synth();
    const configs: string[] = [];
    const walk = (dir: string): void => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name === 'config_generated.py') configs.push(p);
      }
    };
    walk(assembly.directory);
    expect(configs.length).toBeGreaterThan(0);

    const withWebIdentity = configs
      .map((f) => fs.readFileSync(f, 'utf8'))
      .filter((c) => c.includes('WEB_IDENTITY_KEY_REGION'));
    expect(withWebIdentity.length).toBeGreaterThan(0);

    for (const content of withWebIdentity) {
      const line = content
        .split('\n')
        .find((l) => l.startsWith('WEB_IDENTITY_KEY_REGION'));
      expect(line).toBe("WEB_IDENTITY_KEY_REGION = 'ap-southeast-2'");
      // The whole file must carry no unresolved CDK token.
      expect(content).not.toContain('${Token');
      expect(content).not.toContain('Token[');
    }
  });

  test('web-identity on: the distribution serves /.well-known/openid-configuration for STS discovery', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'WiDiscoveryStack', {
      env: { account: '111111111111', region: 'us-east-1' },
    });
    const certificate = acm.Certificate.fromCertificateArn(
      stack,
      'Cert',
      'arn:aws:acm:us-east-1:111111111111:certificate/00000000-0000-0000-0000-000000000000',
    );
    new SecuredCloudFront(stack, 'Secured', {
      defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
      domainNames: ['payload.example.com'],
      certificate: certificate,
      authSsmParamPrefix: '/auth/test',
      authRegion: 'ap-southeast-2',
      enableUserInfoInjection: false,
      enableWebIdentityToken: true,
      webIdentityIssuer: 'https://payload.example.com',
    });

    const template = Template.fromStack(stack);
    // STS AssumeRoleWithWebIdentity GETs <issuer>/.well-known/openid-configuration
    // to discover the jwks_uri; the behaviour must exist on the distribution.
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({ PathPattern: '/.well-known/openid-configuration' }),
        ]),
      }),
    });
  });
});
