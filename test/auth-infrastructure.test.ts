import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AuthInfrastructure } from '../src/cloudfront/patterns/authInfrastructure';

// AuthLambdaFunctions bundles Python lambdas from src/cloudfront/lambda-bundled/*
// (produced by the compile task into lib/cloudfront/lambda-bundled/*). Link them
// so bundling resolves during tests — same shim the session-backend test uses.
beforeAll(() => {
  const srcBundled = path.join(__dirname, '../src/cloudfront/lambda-bundled');
  const libBundled = path.join(__dirname, '../lib/cloudfront/lambda-bundled');
  if (!fs.existsSync(srcBundled) && fs.existsSync(libBundled)) {
    fs.symlinkSync(libBundled, srcBundled, 'dir');
  }
});

describe('AuthInfrastructure — scope token size guard (Entra, 0.0.53)', () => {
  // The config secret's SecretStringTemplate is an `Fn::Join` object (one
  // member is a CFN token), so serialize the whole thing and assert on the
  // embedded JSON literal fragments — same approach as the Cognito backend test.
  function configSecretTemplate(template: Template): string {
    const secrets = template.findResources('AWS::SecretsManager::Secret');
    const configSecret = Object.values(secrets).find(
      (r: any) => typeof r.Properties?.Name === 'string'
        && r.Properties.Name.startsWith('cloudfront-auth-config-'),
    ) as any;
    expect(configSecret).toBeDefined();
    return JSON.stringify(configSecret.Properties.GenerateSecretString.SecretStringTemplate);
  }

  function base(stackId: string, extra: Record<string, unknown> = {}) {
    const app = new core.App();
    const stack = new core.Stack(app, stackId, { env: { account: '123456789012', region: 'ap-southeast-2' } });
    new AuthInfrastructure(stack, 'Auth', {
      zoneName: 'admin.example.com',
      tenantId: 'tenant-123',
      clientId: 'client-abc',
      oauth2CallbackRoleName: 'oauth2-callback-role',
      appSpec: { name: 'admin' },
      ...extra,
    });
    return Template.fromStack(stack);
  }

  test('without scopeTokenMaxBytes the config secret omits the key (byte-for-byte compatible)', () => {
    const tpl = configSecretTemplate(base('NoCapStack'));
    expect(tpl).not.toContain('scope_token_max_bytes');
  });

  test('with scopeTokenMaxBytes the config secret carries the cap', () => {
    const tpl = configSecretTemplate(base('CapStack', { scopeTokenMaxBytes: 6000 }));
    expect(tpl).toContain('\\"scope_token_max_bytes\\":\\"6000\\"');
  });

  test('the existing Entra config keys remain present (no regression)', () => {
    const tpl = configSecretTemplate(base('KeysStack'));
    expect(tpl).toContain('azure_tenant_id');
    expect(tpl).toContain('post_auth_hook_url');
    expect(tpl).toContain('jwt_claims_whitelist');
  });
});
