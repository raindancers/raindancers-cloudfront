import * as core from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { CognitoCustomerPool } from '../src/cloudfront/patterns/cognitoCustomerPool';

function synth(overrides?: Record<string, unknown>): Template {
  const app = new core.App();
  const stack = new core.Stack(app, 'PoolStack', { env: { account: '123456789012', region: 'eu-west-2' } });
  new CognitoCustomerPool(stack, 'Pool', {
    cognitoDomainPrefix: 'shop-brand',
    appClients: [{ key: 'uk', callbackUrls: ['https://uk.example.com/oauth2/callback'] }],
    ...overrides,
  } as never);
  return Template.fromStack(stack);
}

interface ClientProps { ExplicitAuthFlows: string[]; GenerateSecret?: boolean; AllowedOAuthFlows: string[] }
function firstClient(t: Template): ClientProps {
  return (Object.values(t.findResources('AWS::Cognito::UserPoolClient'))[0] as { Properties: ClientProps }).Properties;
}

describe('CognitoCustomerPool', () => {
  test('user pool requires MFA and a 12-char strong password policy', () => {
    synth().hasResourceProperties('AWS::Cognito::UserPool', {
      MfaConfiguration: 'ON',
      Policies: { PasswordPolicy: Match.objectLike({ MinimumLength: 12, RequireSymbols: true }) },
    });
  });

  test('app client is a public PKCE SRP client with no USER_PASSWORD flow', () => {
    const client = firstClient(synth());
    expect(client.GenerateSecret ?? false).toBe(false);
    expect(client.ExplicitAuthFlows).toEqual(expect.arrayContaining(['ALLOW_USER_SRP_AUTH', 'ALLOW_REFRESH_TOKEN_AUTH']));
    expect(client.ExplicitAuthFlows).not.toContain('ALLOW_USER_PASSWORD_AUTH');
    expect(client.ExplicitAuthFlows).not.toContain('ALLOW_ADMIN_USER_PASSWORD_AUTH');
    expect(client.AllowedOAuthFlows).toEqual(['code']);
  });

  test('CUSTOM_AUTH is opt-in', () => {
    expect(firstClient(synth()).ExplicitAuthFlows).not.toContain('ALLOW_CUSTOM_AUTH');
    expect(firstClient(synth({ enableCustomAuthFlow: true })).ExplicitAuthFlows).toContain('ALLOW_CUSTOM_AUTH');
  });

  test('creates one app client per spec (per-brand)', () => {
    synth({
      appClients: [
        { key: 'uk', callbackUrls: ['https://uk.example.com/oauth2/callback'] },
        { key: 'de', callbackUrls: ['https://de.example.com/oauth2/callback'] },
        { key: 'fr', callbackUrls: ['https://fr.example.com/oauth2/callback'] },
      ],
    }).resourceCountIs('AWS::Cognito::UserPoolClient', 3);
  });

  test('enabling SMS adds SMS_MFA', () => {
    synth({ mfaSecondFactor: { otp: true, sms: true } }).hasResourceProperties('AWS::Cognito::UserPool', {
      EnabledMfas: Match.arrayWith(['SMS_MFA', 'SOFTWARE_TOKEN_MFA']),
    });
  });

  test('optional identity pool + ABAC principal tags are created when configured', () => {
    const template = synth({ identityPool: { principalTags: { sub: 'customer-id' } } });
    template.resourceCountIs('AWS::Cognito::IdentityPool', 1);
    template.resourceCountIs('AWS::Cognito::IdentityPoolPrincipalTag', 1);
  });

  test('no identity pool by default', () => {
    synth().resourceCountIs('AWS::Cognito::IdentityPool', 0);
  });

  test('rejects zero app clients', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'Err', { env: { account: '123456789012', region: 'eu-west-2' } });
    expect(() => new CognitoCustomerPool(stack, 'Pool', {
      cognitoDomainPrefix: 'x',
      appClients: [],
    })).toThrow(/at least one app client/);
  });
});
