import * as core from 'aws-cdk-lib';
import {
  aws_certificatemanager as acm,
  aws_cloudfront_origins as origins,
} from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { CognitoCustomUiAuth, CognitoCustomUiAuthProps } from '../src/cloudfront/patterns/cognito-customui-auth';

const RELAY_ARN = 'arn:aws:lambda:eu-west-2:123456789012:function:hook-relay:live';

function synth(over: Partial<CognitoCustomUiAuthProps> = {}, withUrl = true): Template {
  const app = new core.App();
  const stack = new core.Stack(app, 'TestStack', { env: { account: '123456789012', region: 'us-east-1' } });
  const cert = acm.Certificate.fromCertificateArn(stack, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/abc');
  new CognitoCustomUiAuth(stack, 'Auth', {
    domainNames: ['shop.example.com'],
    certificate: cert,
    authSsmParamPrefix: '/auth/shop.example.com',
    authRegion: 'us-east-1',
    ...(withUrl ? { identityLinkingHookUrl: 'https://shop.example.com/hooks/identity' } : {}),
    defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
    ...over,
  });
  return Template.fromStack(stack);
}

/** The keys the custom-UI config secret carries, read from its rendered template. */
function configSecretKeys(template: Template): Record<string, string> {
  const secrets = Object.values(template.findResources('AWS::SecretsManager::Secret')) as any[];
  const secret = secrets.find((s) => s.Properties.Name === 'cloudfront-customui-config-shop.example.com');
  expect(secret).toBeDefined();
  const raw = secret.Properties.SecretString;
  // The kvs_arn value is a deploy-time token, so the string is an Fn::Join. Tokens become <token>.
  const text = typeof raw === 'string'
    ? raw
    : raw['Fn::Join'][1].map((part: unknown) => (typeof part === 'string' ? part : '<token>')).join('');
  return JSON.parse(text);
}

function statements(template: Template): any[] {
  return Object.values(template.findResources('AWS::IAM::Policy')).flatMap(
    (p: any) => p.Properties.PolicyDocument.Statement,
  );
}

const invokeStatements = (template: Template): any[] =>
  statements(template).filter((s) => JSON.stringify(s.Action).includes('lambda:Invoke'));

describe('CognitoCustomUiAuth without a hook relay (unchanged)', () => {
  const template = synth();

  test('the config secret has exactly the three keys it always had', () => {
    expect(Object.keys(configSecretKeys(template)).sort()).toEqual(
      ['kvs_arn', 'post_auth_hook_secret_arn', 'post_auth_hook_url'].sort(),
    );
    expect(configSecretKeys(template).post_auth_hook_url).toBe('https://shop.example.com/hooks/identity');
  });

  test('no role may invoke any Lambda', () => {
    expect(invokeStatements(template)).toEqual([]);
  });

  test('the hook secret grant is still made when a secret ARN is given', () => {
    const t = synth({ identityLinkingHookSecretArn: 'arn:aws:secretsmanager:eu-west-2:123456789012:secret:hook-abc' });
    const grants = statements(t).filter((s) =>
      JSON.stringify(s.Resource).includes('secret:hook-abc'));
    expect(grants.length).toBeGreaterThan(0);
    expect(configSecretKeys(t).post_auth_hook_secret_arn).toBe('arn:aws:secretsmanager:eu-west-2:123456789012:secret:hook-abc');
  });
});

describe('CognitoCustomUiAuth with a hook relay', () => {
  const template = synth({ identityLinkingHookRelayArn: RELAY_ARN }, false);

  test('the config secret names the relay, its region and the timeout, and no URL or secret', () => {
    const keys = configSecretKeys(template);
    expect(keys.post_auth_hook_relay_arn).toBe(RELAY_ARN);
    expect(keys.post_auth_hook_relay_region).toBe('eu-west-2');
    expect(keys.post_auth_hook_relay_timeout).toBe('3');
    expect(keys.post_auth_hook_url).toBe('');
    expect(keys.post_auth_hook_secret_arn).toBe('');
  });

  test('exactly one role gets lambda:InvokeFunction, on exactly the relay ARN', () => {
    const grants = invokeStatements(template);
    expect(grants).toHaveLength(1);
    expect(grants[0]).toEqual({ Action: 'lambda:InvokeFunction', Effect: 'Allow', Resource: RELAY_ARN });
  });

  test('the invoke grant is on the session-issuance role, not the refresh or logout roles', () => {
    const policies = Object.values(template.findResources('AWS::IAM::Policy')) as any[];
    const withInvoke = policies.filter((p) => JSON.stringify(p.Properties.PolicyDocument).includes('lambda:InvokeFunction'));
    expect(withInvoke).toHaveLength(1);
    const roleRefs = JSON.stringify(withInvoke[0].Properties.Roles);
    expect(roleRefs).toContain('IssuanceRole');
  });

  test('no hook secret grant is made', () => {
    expect(JSON.stringify(statements(template))).not.toContain('hook-abc');
  });

  test('the region is taken from the ARN, and an explicit region and timeout win', () => {
    const t = synth({
      identityLinkingHookRelayArn: RELAY_ARN,
      identityLinkingHookRelayRegion: 'eu-west-1',
      identityLinkingHookRelayTimeoutSeconds: 5,
    }, false);
    expect(configSecretKeys(t).post_auth_hook_relay_region).toBe('eu-west-1');
    expect(configSecretKeys(t).post_auth_hook_relay_timeout).toBe('5');
  });

  test('a function ARN without an alias is accepted as it is', () => {
    const arn = 'arn:aws:lambda:eu-west-2:123456789012:function:hook-relay';
    const t = synth({ identityLinkingHookRelayArn: arn }, false);
    expect(invokeStatements(t)[0].Resource).toBe(arn);
  });
});

describe('hook URL or relay: exactly one', () => {
  test('both is refused', () => {
    expect(() => synth({ identityLinkingHookRelayArn: RELAY_ARN })).toThrow(/not both/);
  });

  test('neither is refused', () => {
    expect(() => synth({}, false)).toThrow(/identityLinkingHookUrl or identityLinkingHookRelayArn is required/);
  });

  test('a relay with a hook secret ARN is refused', () => {
    expect(() =>
      synth({ identityLinkingHookRelayArn: RELAY_ARN, identityLinkingHookSecretArn: 'arn:aws:secretsmanager:eu-west-2:1:secret:x' }, false),
    ).toThrow(/identityLinkingHookSecretArn is not used/);
  });

  test('a deploy-time relay ARN needs a region', () => {
    const build = (region?: string) => {
      const app = new core.App();
      const stack = new core.Stack(app, 'T', { env: { account: '123456789012', region: 'us-east-1' } });
      const cert = acm.Certificate.fromCertificateArn(stack, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/abc');
      const arn = new core.CfnParameter(stack, 'RelayArn', { type: 'String' }).valueAsString;
      return new CognitoCustomUiAuth(stack, 'Auth', {
        domainNames: ['shop.example.com'],
        certificate: cert,
        authSsmParamPrefix: '/auth/shop.example.com',
        authRegion: 'us-east-1',
        identityLinkingHookRelayArn: arn,
        identityLinkingHookRelayRegion: region,
        defaultBehavior: { origin: new origins.HttpOrigin('origin.example.com') },
      });
    };
    expect(() => build()).toThrow(/identityLinkingHookRelayRegion is required/);
    expect(() => build('eu-west-2')).not.toThrow();
  });

  test('a string that is not an ARN is refused', () => {
    expect(() => synth({ identityLinkingHookRelayArn: 'hook-relay' }, false)).toThrow(/is not a Lambda ARN/);
  });
});
