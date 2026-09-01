import * as core from 'aws-cdk-lib';
import {
  aws_certificatemanager as acm,
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
} from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { CognitoCustomUiAuth } from '../src/cloudfront/patterns/cognito-customui-auth';
import { Extension } from '../src/cloudfront/patterns/securedCloudFront';

function synth(configure?: (auth: CognitoCustomUiAuth) => void): Template {
  const app = new core.App();
  const stack = new core.Stack(app, 'TestStack', { env: { account: '123456789012', region: 'us-east-1' } });
  const cert = acm.Certificate.fromCertificateArn(stack, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/abc');
  const auth = new CognitoCustomUiAuth(stack, 'Auth', {
    domainNames: ['shop.example.com'],
    certificate: cert,
    authSsmParamPrefix: '/auth/shop.example.com',
    authRegion: 'us-east-1',
    identityLinkingHookUrl: 'https://shop.example.com/hooks/identity',
    defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
  });
  if (configure) {
    configure(auth);
  }
  return Template.fromStack(stack);
}

describe('CognitoCustomUiAuth synthesis', () => {
  test('creates a CloudFront distribution', () => {
    synth().resourceCountIs('AWS::CloudFront::Distribution', 1);
  });

  test('accepts a configSecretName override without breaking synthesis', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'OverrideStack', { env: { account: '123456789012', region: 'us-east-1' } });
    const cert = acm.Certificate.fromCertificateArn(stack, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/abc');
    new CognitoCustomUiAuth(stack, 'Auth', {
      domainNames: ['shop.example.com'],
      configSecretName: 'cognito-auth-config-shop.example.com',
      certificate: cert,
      authSsmParamPrefix: '/cognito-auth/shop.example.com',
      authRegion: 'us-east-1',
      identityLinkingHookUrl: 'https://shop.example.com/hooks/identity',
      defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
    });
    Template.fromStack(stack).resourceCountIs('AWS::CloudFront::Distribution', 1);
  });

  test('mounts session-issuance, refresh and logout behaviours', () => {
    const template = synth();
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({ PathPattern: '/auth/session' }),
          Match.objectLike({ PathPattern: '/oauth2/refresh' }),
          Match.objectLike({ PathPattern: '/oauth2/logout' }),
        ]),
      }),
    });
  });

  test('the auth endpoint behaviours disable caching (Set-Cookie must reach the viewer)', () => {
    const template = synth();
    // CACHING_DISABLED is the AWS managed policy id.
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({ PathPattern: '/auth/session', CachePolicyId: '4135ea2d-6df8-44a3-9df3-4b5a84be39ad' }),
        ]),
      }),
    });
  });

  test('provisions the custom-UI config secret', () => {
    synth().hasResourceProperties('AWS::SecretsManager::Secret', {
      Name: 'cloudfront-customui-config-shop.example.com',
    });
  });

  test('attaches a WAF web ACL when webAclId is provided (create mode)', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'WafStack', { env: { account: '123456789012', region: 'us-east-1' } });
    const cert = acm.Certificate.fromCertificateArn(stack, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/abc');
    new CognitoCustomUiAuth(stack, 'Auth', {
      domainNames: ['shop.example.com'],
      certificate: cert,
      authSsmParamPrefix: '/auth/shop.example.com',
      authRegion: 'us-east-1',
      identityLinkingHookUrl: 'https://shop.example.com/hooks/identity',
      webAclId: 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/abc',
      defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
    });
    Template.fromStack(stack).hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({ WebACLId: 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/abc' }),
    });
  });

  test('a protected behaviour attaches a viewer-request function', () => {
    const template = synth((auth) => {
      auth.addBehavior('/account/*', new origins.HttpOrigin('origin.example.com'), { extensions: [Extension.REQUIRE_AUTH] });
    });
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({
            PathPattern: '/account/*',
            FunctionAssociations: Match.arrayWith([
              Match.objectLike({ EventType: 'viewer-request' }),
            ]),
          }),
        ]),
      }),
    });
  });

  test('omitting refresh/logout endpoints drops their behaviours', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'S2', { env: { account: '123456789012', region: 'us-east-1' } });
    const cert = acm.Certificate.fromCertificateArn(stack, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/abc');
    new CognitoCustomUiAuth(stack, 'Auth', {
      domainNames: ['shop.example.com'],
      certificate: cert,
      authSsmParamPrefix: '/auth/shop.example.com',
      authRegion: 'us-east-1',
      identityLinkingHookUrl: 'https://shop.example.com/hooks/identity',
      enableRefreshEndpoint: false,
      enableLogoutEndpoint: false,
      defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
    });
    const template = Template.fromStack(stack);
    const behaviors = template.toJSON().Resources;
    const distsJson = JSON.stringify(behaviors);
    expect(distsJson).toContain('/auth/session');
    expect(distsJson).not.toContain('/oauth2/refresh');
    expect(distsJson).not.toContain('/oauth2/logout');
  });
});

describe('CognitoCustomUiAuth attach mode', () => {
  function attachStack(): { stack: core.Stack; dist: cloudfront.Distribution; auth: CognitoCustomUiAuth } {
    const app = new core.App();
    const stack = new core.Stack(app, 'AttachStack', { env: { account: '123456789012', region: 'us-east-1' } });
    const dist = new cloudfront.Distribution(stack, 'Existing', {
      defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
    });
    const auth = new CognitoCustomUiAuth(stack, 'Auth', {
      domainNames: ['shop.example.com'],
      authSsmParamPrefix: '/auth/shop.example.com',
      authRegion: 'us-east-1',
      identityLinkingHookUrl: 'https://shop.example.com/hooks/identity',
      distribution: dist,
      authEndpointOrigin: new origins.HttpOrigin('origin.example.com'),
    });
    return { stack, dist, auth };
  }

  test('adds auth endpoints to the passed distribution without creating a new one', () => {
    const { stack } = attachStack();
    const template = Template.fromStack(stack);
    template.resourceCountIs('AWS::CloudFront::Distribution', 1);
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({ PathPattern: '/auth/session' }),
          Match.objectLike({ PathPattern: '/oauth2/refresh' }),
          Match.objectLike({ PathPattern: '/oauth2/logout' }),
        ]),
      }),
    });
  });

  test('protect() adds a viewer-request auth function on a protected path', () => {
    const { stack, auth } = attachStack();
    auth.protect('/account/*', new origins.HttpOrigin('origin.example.com'));
    const template = Template.fromStack(stack);
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({
            PathPattern: '/account/*',
            FunctionAssociations: Match.arrayWith([Match.objectLike({ EventType: 'viewer-request' })]),
          }),
        ]),
      }),
    });
  });

  test('exposes a composed authFunction for the consumer to compose elsewhere', () => {
    const { auth } = attachStack();
    expect(auth.authFunction).toBeDefined();
  });

  test('attach mode requires authEndpointOrigin', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'AttachErr', { env: { account: '123456789012', region: 'us-east-1' } });
    const dist = new cloudfront.Distribution(stack, 'Existing', {
      defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
    });
    expect(() => new CognitoCustomUiAuth(stack, 'Auth', {
      domainNames: ['shop.example.com'],
      authSsmParamPrefix: '/auth/shop.example.com',
      authRegion: 'us-east-1',
      identityLinkingHookUrl: 'https://shop.example.com/hooks/identity',
      distribution: dist,
    })).toThrow(/authEndpointOrigin is required/);
  });

  test('create mode requires defaultBehavior and certificate', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'CreateErr', { env: { account: '123456789012', region: 'us-east-1' } });
    expect(() => new CognitoCustomUiAuth(stack, 'Auth', {
      domainNames: ['shop.example.com'],
      authSsmParamPrefix: '/auth/shop.example.com',
      authRegion: 'us-east-1',
      identityLinkingHookUrl: 'https://shop.example.com/hooks/identity',
    })).toThrow(/defaultBehavior and certificate are required/);
  });
});

describe('CognitoCustomUiAuth default-behaviour functions (no L1 override)', () => {
  function stackWithGeo() {
    const app = new core.App();
    const stack = new core.Stack(app, 'GeoStack', { env: { account: '123456789012', region: 'us-east-1' } });
    const cert = acm.Certificate.fromCertificateArn(stack, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/abc');
    const geo = new cloudfront.Function(stack, 'Geo', {
      code: cloudfront.FunctionCode.fromInline('function handler(event){return event.request}'),
      runtime: cloudfront.FunctionRuntime.JS_2_0,
    });
    return { app, stack, cert, geo };
  }

  test('a consumer viewer-request function on the PUBLIC default behaviour is attached natively', () => {
    const { stack, cert, geo } = stackWithGeo();
    new CognitoCustomUiAuth(stack, 'Auth', {
      domainNames: ['shop.example.com'],
      certificate: cert,
      authSsmParamPrefix: '/auth/shop.example.com',
      authRegion: 'us-east-1',
      identityLinkingHookUrl: 'https://shop.example.com/hooks/identity',
      defaultBehavior: {
        origin: new origins.HttpOrigin('origin.example.com'),
        functionAssociations: [{ function: geo, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }],
      },
    });
    Template.fromStack(stack).hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        DefaultCacheBehavior: Match.objectLike({
          FunctionAssociations: Match.arrayWith([Match.objectLike({ EventType: 'viewer-request' })]),
        }),
      }),
    });
  });

  test('throws if auth and a consumer function both claim viewer-request on the default behaviour', () => {
    const { stack, cert, geo } = stackWithGeo();
    expect(() => new CognitoCustomUiAuth(stack, 'Auth', {
      domainNames: ['shop.example.com'],
      certificate: cert,
      authSsmParamPrefix: '/auth/shop.example.com',
      authRegion: 'us-east-1',
      identityLinkingHookUrl: 'https://shop.example.com/hooks/identity',
      defaultExtensions: [Extension.REQUIRE_AUTH],
      defaultBehavior: {
        origin: new origins.HttpOrigin('origin.example.com'),
        functionAssociations: [{ function: geo, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }],
      },
    })).toThrow(/one function per event type per behaviour/);
  });
});
