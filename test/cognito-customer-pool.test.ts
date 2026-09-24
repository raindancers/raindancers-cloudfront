import * as core from 'aws-cdk-lib';
import { aws_kms as kms, aws_lambda as lambda } from 'aws-cdk-lib';
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

  describe('custom email sender + EMAIL_OTP MFA', () => {
    function withSender(stack: core.Stack, extra?: Record<string, unknown>) {
      const fn = new lambda.Function(stack, 'Sender', {
        runtime: lambda.Runtime.NODEJS_20_X,
        handler: 'index.handler',
        code: lambda.Code.fromInline('exports.handler = async () => {};'),
      });
      const key = new kms.Key(stack, 'SenderKey');
      return new CognitoCustomerPool(stack, 'Pool', {
        cognitoDomainPrefix: 'shop-brand',
        appClients: [{ key: 'uk', callbackUrls: ['https://uk.example.com/oauth2/callback'] }],
        customEmailSenderLambda: fn,
        customSenderKmsKey: key,
        ...extra,
      } as never);
    }

    test('wires the CUSTOM_EMAIL_SENDER trigger and KMS key when both props are set', () => {
      const app = new core.App();
      const stack = new core.Stack(app, 'S', { env: { account: '123456789012', region: 'eu-west-2' } });
      withSender(stack);
      const t = Template.fromStack(stack);
      t.hasResourceProperties('AWS::Cognito::UserPool', {
        LambdaConfig: Match.objectLike({
          CustomEmailSender: Match.objectLike({ LambdaArn: Match.anyValue(), LambdaVersion: 'V1_0' }),
          KMSKeyID: Match.anyValue(),
        }),
      });
    });

    test('emailOtpMfa sets EnabledMfas to EMAIL_OTP only (via L1) and never TOTP/SMS', () => {
      const app = new core.App();
      const stack = new core.Stack(app, 'S', { env: { account: '123456789012', region: 'eu-west-2' } });
      withSender(stack, { emailOtpMfa: true });
      const t = Template.fromStack(stack);
      t.hasResourceProperties('AWS::Cognito::UserPool', {
        MfaConfiguration: 'ON',
        EnabledMfas: ['EMAIL_OTP'],
      });
      // Property P4: the email-only pool never carries the other factors.
      const pool = Object.values(t.findResources('AWS::Cognito::UserPool'))[0] as { Properties: { EnabledMfas: string[] } };
      expect(pool.Properties.EnabledMfas).not.toContain('SOFTWARE_TOKEN_MFA');
      expect(pool.Properties.EnabledMfas).not.toContain('SMS_MFA');
    });

    test('emailOtpMfa uses admin_only account recovery, never verified_email (Cognito rejects EMAIL_OTP + email-only recovery)', () => {
      const app = new core.App();
      const stack = new core.Stack(app, 'S', { env: { account: '123456789012', region: 'eu-west-2' } });
      withSender(stack, { emailOtpMfa: true });
      const t = Template.fromStack(stack);
      // Cognito rejects EmailMfaConfiguration when the only recovery mechanism is
      // verified_email. The construct must fall back to admin_only (AccountRecovery.NONE).
      t.hasResourceProperties('AWS::Cognito::UserPool', {
        AccountRecoverySetting: {
          RecoveryMechanisms: [{ Name: 'admin_only', Priority: 1 }],
        },
      });
      const pool = Object.values(t.findResources('AWS::Cognito::UserPool'))[0] as {
        Properties: { AccountRecoverySetting: { RecoveryMechanisms: Array<{ Name: string }> } };
      };
      const names = pool.Properties.AccountRecoverySetting.RecoveryMechanisms.map((m) => m.Name);
      expect(names).not.toContain('verified_email');
      expect(names).not.toContain('verified_phone_number');
    });

    test('baseline unchanged: no custom sender props => no CustomEmailSender / KMSKeyID', () => {
      const t = synth();
      const pool = Object.values(t.findResources('AWS::Cognito::UserPool'))[0] as { Properties: { LambdaConfig?: Record<string, unknown>; AccountRecoverySetting?: { RecoveryMechanisms: Array<{ Name: string }> } } };
      const lambdaConfig = pool.Properties.LambdaConfig ?? {};
      expect(lambdaConfig).not.toHaveProperty('CustomEmailSender');
      expect(lambdaConfig).not.toHaveProperty('KMSKeyID');
      // Baseline pool keeps email-only recovery (no emailOtpMfa in play).
      expect(pool.Properties.AccountRecoverySetting?.RecoveryMechanisms).toEqual([{ Name: 'verified_email', Priority: 1 }]);
    });

    test('rejects the Lambda without the KMS key (and vice versa)', () => {
      const app = new core.App();
      const stack = new core.Stack(app, 'S', { env: { account: '123456789012', region: 'eu-west-2' } });
      const fn = new lambda.Function(stack, 'Sender', {
        runtime: lambda.Runtime.NODEJS_20_X,
        handler: 'index.handler',
        code: lambda.Code.fromInline('exports.handler = async () => {};'),
      });
      expect(() => new CognitoCustomerPool(stack, 'P1', {
        cognitoDomainPrefix: 'x',
        appClients: [{ key: 'uk' }],
        customEmailSenderLambda: fn,
      } as never)).toThrow(/must be provided together/);
      expect(() => new CognitoCustomerPool(stack, 'P2', {
        cognitoDomainPrefix: 'x',
        appClients: [{ key: 'uk' }],
        customSenderKmsKey: new kms.Key(stack, 'K'),
      } as never)).toThrow(/must be provided together/);
    });

    test('rejects emailOtpMfa without a custom email sender', () => {
      const app = new core.App();
      const stack = new core.Stack(app, 'S', { env: { account: '123456789012', region: 'eu-west-2' } });
      expect(() => new CognitoCustomerPool(stack, 'P', {
        cognitoDomainPrefix: 'x',
        appClients: [{ key: 'uk' }],
        emailOtpMfa: true,
      } as never)).toThrow(/emailOtpMfa requires customEmailSenderLambda/);
    });
  });
});
