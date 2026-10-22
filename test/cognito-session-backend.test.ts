import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { CognitoAuthInfrastructure } from '../src/cloudfront/patterns/cognitoAuthInfrastructure';
import { CognitoSessionBackend } from '../src/cloudfront/patterns/cognitoSessionBackend';

// AuthLambdaFunctions bundles Python lambdas from src/cloudfront/lambda-bundled/*
// (produced by the compile task into lib/cloudfront/lambda-bundled/*). Link them
// so bundling resolves during tests — same shim the callback-cache test uses.
beforeAll(() => {
  const srcBundled = path.join(__dirname, '../src/cloudfront/lambda-bundled');
  const libBundled = path.join(__dirname, '../lib/cloudfront/lambda-bundled');
  if (!fs.existsSync(srcBundled) && fs.existsSync(libBundled)) {
    fs.symlinkSync(libBundled, srcBundled, 'dir');
  }
});

describe('CognitoSessionBackend', () => {
  function synth(): Template {
    const app = new core.App();
    const stack = new core.Stack(app, 'BackendStack', { env: { account: '123456789012', region: 'eu-west-2' } });
    new CognitoSessionBackend(stack, 'Backend', {
      domainName: 'shop.example.com',
      userPoolId: 'eu-west-2_abc123',
      clientId: 'client-abc',
      cognitoDomain: 'shop-brand.auth.eu-west-2.amazoncognito.com',
    });
    return Template.fromStack(stack);
  }

  test('creates the config secret named for the domain', () => {
    synth().hasResourceProperties('AWS::SecretsManager::Secret', {
      Name: 'cloudfront-auth-config-shop.example.com',
    });
  });

  test('overrides the config secret name when configSecretName is provided', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'OverrideStack', { env: { account: '123456789012', region: 'eu-west-2' } });
    new CognitoSessionBackend(stack, 'Backend', {
      domainName: 'shop.example.com',
      configSecretName: 'cognito-auth-config-shop.example.com',
      userPoolId: 'eu-west-2_abc123',
      clientId: 'client-abc',
      cognitoDomain: 'shop-brand.auth.eu-west-2.amazoncognito.com',
    });
    Template.fromStack(stack).hasResourceProperties('AWS::SecretsManager::Secret', {
      Name: 'cognito-auth-config-shop.example.com',
    });
  });

  test('creates the auth-security DynamoDB table', () => {
    synth().resourceCountIs('AWS::DynamoDB::Table', 1);
  });

  test('creates the HMAC KMS key', () => {
    synth().resourceCountIs('AWS::KMS::Key', 1);
  });
});

describe('CognitoSessionBackend — Scope Resolver (opt-in)', () => {
  // The config secret's SecretStringTemplate is an `Fn::Join` object (one
  // member is a CFN token for the table name), so serialize the whole thing to
  // a string and assert on the embedded JSON literal fragments.
  function configSecretTemplate(template: Template): string {
    const secrets = template.findResources('AWS::SecretsManager::Secret');
    const configSecret = Object.values(secrets).find(
      (r: any) => typeof r.Properties?.Name === 'string'
        && r.Properties.Name.startsWith('cloudfront-auth-config-'),
    ) as any;
    expect(configSecret).toBeDefined();
    return JSON.stringify(configSecret.Properties.GenerateSecretString.SecretStringTemplate);
  }

  test('without scopeResolver the config secret carries no resolver keys (R1.3)', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'NoResolverStack', { env: { account: '123456789012', region: 'eu-west-2' } });
    new CognitoSessionBackend(stack, 'Backend', {
      domainName: 'shop.example.com',
      userPoolId: 'eu-west-2_abc123',
      clientId: 'client-abc',
      cognitoDomain: 'shop-brand.auth.eu-west-2.amazoncognito.com',
    });
    const tpl = configSecretTemplate(Template.fromStack(stack));
    expect(tpl).not.toContain('scope_resolver_url');
    expect(tpl).not.toContain('scope_resolver_secret_arn');
    expect(tpl).not.toContain('scope_token_max_bytes');
  });

  test('with scopeResolver the config secret carries the resolver url, timeout and size cap (R1.1, R2.1)', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'ResolverStack', { env: { account: '123456789012', region: 'eu-west-2' } });
    new CognitoSessionBackend(stack, 'Backend', {
      domainName: 'shop.example.com',
      userPoolId: 'eu-west-2_abc123',
      clientId: 'client-abc',
      cognitoDomain: 'shop-brand.auth.eu-west-2.amazoncognito.com',
      scopeResolver: {
        endpointUrl: 'https://resolver.example.com/scope',
        timeoutSeconds: 5,
      },
      scopeTokenMaxBytes: 6000,
    });
    const tpl = configSecretTemplate(Template.fromStack(stack));
    expect(tpl).toContain('\\"scope_resolver_url\\":\\"https://resolver.example.com/scope\\"');
    expect(tpl).toContain('\\"scope_resolver_timeout\\":\\"5\\"');
    expect(tpl).toContain('\\"scope_token_max_bytes\\":\\"6000\\"');
    // No shared secret configured => empty, not absent.
    expect(tpl).toContain('\\"scope_resolver_secret_arn\\":\\"\\"');
  });

  test('defaults timeout to 3 and size cap to 7168 when unset (R5.1)', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'ResolverDefaultsStack', { env: { account: '123456789012', region: 'eu-west-2' } });
    new CognitoSessionBackend(stack, 'Backend', {
      domainName: 'shop.example.com',
      userPoolId: 'eu-west-2_abc123',
      clientId: 'client-abc',
      cognitoDomain: 'shop-brand.auth.eu-west-2.amazoncognito.com',
      scopeResolver: { endpointUrl: 'https://resolver.example.com/scope' },
    });
    const tpl = configSecretTemplate(Template.fromStack(stack));
    expect(tpl).toContain('\\"scope_resolver_timeout\\":\\"3\\"');
    expect(tpl).toContain('\\"scope_token_max_bytes\\":\\"7168\\"');
  });
});

describe('CognitoAuthInfrastructure facade', () => {
  function synth(): Template {
    const app = new core.App();
    const stack = new core.Stack(app, 'FacadeStack', { env: { account: '123456789012', region: 'eu-west-2' } });
    new CognitoAuthInfrastructure(stack, 'Auth', {
      zoneName: 'shop.example.com',
      appSpec: { name: 'shop' },
      cognitoDomainPrefix: 'shop-brand',
    });
    return Template.fromStack(stack);
  }

  test('still provisions a user pool and the config secret (backward-compatible surface)', () => {
    const template = synth();
    template.resourceCountIs('AWS::Cognito::UserPool', 1);
    template.hasResourceProperties('AWS::SecretsManager::Secret', {
      Name: 'cloudfront-auth-config-shop.example.com',
    });
  });

  test('preserves the legacy fixed audit bucket name', () => {
    synth().hasResourceProperties('AWS::S3::Bucket', {
      BucketName: 'auth-audit-logs-cognito-123456789012-eu-west-2',
    });
  });
});
