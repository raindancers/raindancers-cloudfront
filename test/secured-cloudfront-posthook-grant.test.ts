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
 * Regression for the #195 login 503 "Identity resolution unavailable".
 *
 * The edge mint calls an IAM-gated (AWS_IAM) Lambda Function URL resolver,
 * SigV4-signed. For a SAME-ACCOUNT caller of an AWS_IAM Function URL, AWS
 * authorizes through the CALLER'S IDENTITY policy — a resource-based policy on
 * the resolver does not suffice. Without an identity-side grant the signed edge
 * call is refused 403 and, fail-closed, the mint returns a 503. Setting
 * postAuthHookFunctionArn must grant the edge role lambda:InvokeFunctionUrl (and
 * lambda:InvokeFunction) on that function ARN.
 */
describe('SecuredCloudFront post-auth hook invoke grant', () => {
  const RESOLVER_ARN =
    'arn:aws:lambda:ap-southeast-2:111111111111:function:authority-resolver';

  beforeAll(() => {
    const srcBundled = path.join(__dirname, '../src/cloudfront/lambda-bundled');
    const libBundled = path.join(__dirname, '../lib/cloudfront/lambda-bundled');
    if (!fs.existsSync(srcBundled) && fs.existsSync(libBundled)) {
      fs.symlinkSync(libBundled, srcBundled, 'dir');
    }
  });

  function synth(withArn: boolean): Template {
    const app = new core.App();
    const stack = new core.Stack(app, 'TestStack', {
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
      certificate,
      authSsmParamPrefix: '/auth/test',
      authRegion: 'us-east-1',
      enableUserInfoInjection: false,
      postAuthHookUrl: 'https://resolver.lambda-url.ap-southeast-2.on.aws/',
      postAuthHookFunctionArn: withArn ? RESOLVER_ARN : undefined,
    });
    return Template.fromStack(stack);
  }

  test('grants the edge role InvokeFunctionUrl + InvokeFunction on the resolver when the ARN is set', () => {
    const template = synth(true);
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Action: Match.arrayWith(['lambda:InvokeFunctionUrl', 'lambda:InvokeFunction']),
            Resource: RESOLVER_ARN,
          }),
        ]),
      }),
    });
  });

  test('does NOT grant Function URL invoke when no ARN is given (no over-grant)', () => {
    const template = synth(false);
    const policies = template.findResources('AWS::IAM::Policy');
    const blob = JSON.stringify(Object.values(policies));
    expect(blob).not.toContain('lambda:InvokeFunctionUrl');
  });
});
