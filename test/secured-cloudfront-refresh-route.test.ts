import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront_origins as origins,
  aws_certificatemanager as acm,
} from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { SecuredCloudFront } from '../src/cloudfront/patterns/securedCloudFront';

/**
 * With the two-token model on, /oauth2/refresh must be served by the OAuth
 * callback EdgeFunction (the only function that may re-mint the RS256
 * web_identity cookie), not the standalone HMAC-only refresh Lambda. Otherwise
 * a refresh would renew auth_session but leave web_identity expired.
 */
describe('SecuredCloudFront /oauth2/refresh routing', () => {
  beforeAll(() => {
    const srcBundled = path.join(__dirname, '../src/cloudfront/lambda-bundled');
    const libBundled = path.join(__dirname, '../lib/cloudfront/lambda-bundled');
    if (!fs.existsSync(srcBundled) && fs.existsSync(libBundled)) {
      fs.symlinkSync(libBundled, srcBundled, 'dir');
    }
  });

  function synth(opts: { webIdentity: boolean; refresh: boolean }): Template {
    const app = new core.App();
    const stack = new core.Stack(app, 'TestStack', {
      env: { account: '111111111111', region: 'us-east-1' },
    });
    const certificate = acm.Certificate.fromCertificateArn(
      stack, 'Cert',
      'arn:aws:acm:us-east-1:111111111111:certificate/00000000-0000-0000-0000-000000000000',
    );
    new SecuredCloudFront(stack, 'Secured', {
      defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
      domainNames: ['admin.example.com'],
      certificate,
      authSsmParamPrefix: '/auth/test',
      authRegion: 'us-east-1',
      enableUserInfoInjection: false,
      enableRefreshEndpoint: opts.refresh,
      enableWebIdentityToken: opts.webIdentity,
      webIdentityIssuer: opts.webIdentity ? 'https://admin.example.com' : undefined,
    });
    return Template.fromStack(stack);
  }

  function refreshBehavior(template: Template): any {
    const dist = Object.values(template.findResources('AWS::CloudFront::Distribution'))[0] as any;
    const behaviors: any[] = dist.Properties.DistributionConfig.CacheBehaviors ?? [];
    return behaviors.find((b) => b.PathPattern === '/oauth2/refresh');
  }

  function lambdaIdOf(behavior: any): string {
    return JSON.stringify(behavior.LambdaFunctionAssociations[0].LambdaFunctionARN);
  }

  test('web_identity on: refresh is served by the callback function, no separate refresh Lambda', () => {
    const template = synth({ webIdentity: true, refresh: true });
    const refresh = refreshBehavior(template);
    expect(refresh).toBeDefined();
    const sw = (Object.values(template.findResources('AWS::CloudFront::Distribution'))[0] as any)
      .Properties.DistributionConfig.CacheBehaviors.find((b: any) => b.PathPattern === '/oauth2/switch');
    expect(lambdaIdOf(refresh)).toEqual(lambdaIdOf(sw));
    expect(JSON.stringify(template.toJSON())).not.toContain('RefreshEndpoint');
  });

  test('web_identity off: the standalone refresh Lambda is still used', () => {
    const template = synth({ webIdentity: false, refresh: true });
    expect(refreshBehavior(template)).toBeDefined();
    expect(JSON.stringify(template.toJSON())).toContain('RefreshEndpoint');
  });

  test('refresh off: no /oauth2/refresh behavior', () => {
    const template = synth({ webIdentity: true, refresh: false });
    expect(refreshBehavior(template)).toBeUndefined();
  });
});
