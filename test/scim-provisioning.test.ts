import * as core from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { ScimProvisioningService, ScimAuthMode } from '../src/cloudfront/patterns/scimProvisioningService';

function synth(props = {}, id = 'Scim'): Template {
  const app = new core.App();
  const stack = new core.Stack(app, 'ScimStack', { env: { account: '123456789012', region: 'eu-west-2' } });
  new ScimProvisioningService(stack, id, props);
  return Template.fromStack(stack);
}

describe('ScimProvisioningService', () => {
  describe('OAUTH_CLIENT_CREDENTIALS (default)', () => {
    const t = () => synth();

    test('creates a dedicated DynamoDB table, pay-per-request, retain-on-update-or-delete', () => {
      const tpl = t();
      tpl.hasResourceProperties('AWS::DynamoDB::Table', {
        BillingMode: 'PAY_PER_REQUEST',
      });
      // RETAIN_ON_UPDATE_OR_DELETE -> DeletionPolicy RetainExceptOnCreate
      tpl.hasResource('AWS::DynamoDB::Table', { DeletionPolicy: 'RetainExceptOnCreate' });
    });

    test('table name is not hardcoded (CDK auto-generated)', () => {
      const tbl = Object.values(t().findResources('AWS::DynamoDB::Table'))[0] as any;
      expect(tbl.Properties.TableName).toBeUndefined();
    });

    test('creates an RSA sign/verify KMS key', () => {
      t().hasResourceProperties('AWS::KMS::Key', {
        KeySpec: 'RSA_2048',
        KeyUsage: 'SIGN_VERIFY',
      });
    });

    test('creates a client secret with no generated (random) value', () => {
      // An out-of-band secret must NOT carry GenerateSecretString (that would
      // mint a random value); it seeds an explicit placeholder instead.
      const secrets = t().findResources('AWS::SecretsManager::Secret');
      const vals = Object.values(secrets) as any[];
      expect(vals.length).toBe(1);
      expect(vals[0].Properties.GenerateSecretString).toBeUndefined();
      expect(vals[0].Properties.SecretString).toBeDefined();
    });

    test('Function URL auth type is NONE (auth is in the handler)', () => {
      t().hasResourceProperties('AWS::Lambda::Url', { AuthType: 'NONE' });
    });

    test('lambda is Python 3.12', () => {
      t().hasResourceProperties('AWS::Lambda::Function', { Runtime: 'python3.12' });
    });
  });

  describe('AWS_IAM mode', () => {
    const t = () => synth({ authMode: ScimAuthMode.AWS_IAM });

    test('Function URL auth type is AWS_IAM', () => {
      t().hasResourceProperties('AWS::Lambda::Url', { AuthType: 'AWS_IAM' });
    });

    test('no KMS signing key and no secret in AWS_IAM mode', () => {
      const tpl = t();
      expect(Object.keys(tpl.findResources('AWS::KMS::Key')).length).toBe(0);
      expect(Object.keys(tpl.findResources('AWS::SecretsManager::Secret')).length).toBe(0);
    });
  });

  describe('STATIC_BEARER mode', () => {
    const t = () => synth({ authMode: ScimAuthMode.STATIC_BEARER });

    test('creates a static bearer secret and no KMS key', () => {
      const tpl = t();
      expect(Object.keys(tpl.findResources('AWS::SecretsManager::Secret')).length).toBe(1);
      expect(Object.keys(tpl.findResources('AWS::KMS::Key')).length).toBe(0);
    });
  });

  describe('WIF mode', () => {
    test('requires wif config', () => {
      expect(() => synth({ authMode: ScimAuthMode.WIF })).toThrow(/requires the `wif`/);
    });

    test('creates a KMS key and no client/bearer secret', () => {
      const tpl = synth({
        authMode: ScimAuthMode.WIF,
        wif: {
          assertionIssuer: 'https://login.microsoftonline.com/tid/v2.0',
          assertionJwksUri: 'https://login.microsoftonline.com/tid/discovery/v2.0/keys',
          expectedAudience: 'api://app-id',
          expectedAzp: 'prov-client-id',
        },
      });
      expect(Object.keys(tpl.findResources('AWS::KMS::Key')).length).toBe(1);
      expect(Object.keys(tpl.findResources('AWS::SecretsManager::Secret')).length).toBe(0);
    });
  });

  describe('least-privilege IAM', () => {
    test('the lambda role carries no Resource:"*" item/kms/secret grant', () => {
      const tpl = synth();
      const policies = tpl.findResources('AWS::IAM::Policy');
      for (const pol of Object.values(policies) as any[]) {
        for (const stmt of pol.Properties.PolicyDocument.Statement) {
          const actions: string[] = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
          const guarded = actions.some(a =>
            a.startsWith('dynamodb:') || a.startsWith('kms:') || a.startsWith('secretsmanager:'));
          if (guarded) {
            expect(stmt.Resource).not.toEqual('*');
          }
        }
      }
    });
  });

  describe('reusability', () => {
    test('two instances coexist in one stack with no name collision', () => {
      const app = new core.App();
      const stack = new core.Stack(app, 'MultiStack', { env: { account: '123456789012', region: 'eu-west-2' } });
      new ScimProvisioningService(stack, 'ScimA', {});
      new ScimProvisioningService(stack, 'ScimB', {});
      const tpl = Template.fromStack(stack);
      // Two of each core resource, no throw on synth.
      expect(Object.keys(tpl.findResources('AWS::DynamoDB::Table')).length).toBe(2);
      expect(Object.keys(tpl.findResources('AWS::Lambda::Url')).length).toBe(2);
    });

    test('no hardcoded consumer/brand values appear in the table', () => {
      const tbl = Object.values(synth().findResources('AWS::DynamoDB::Table'))[0] as any;
      expect(JSON.stringify(tbl)).not.toMatch(/horton|admin\.horton|entra/i);
    });
  });
});
