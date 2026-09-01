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
