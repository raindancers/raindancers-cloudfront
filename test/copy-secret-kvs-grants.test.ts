import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AuthInfrastructure } from '../src/cloudfront/patterns/authInfrastructure';

/**
 * The copy-secret Lambda (lambda/hmacSecret) calls GetKey twice: to keep the current jwt.secret as
 * jwt.secret.old, and to read jwt.secret back after the write and check it matches Secrets Manager.
 * Its role must allow GetKey, or every Update of the SecretCopyResource custom resource fails with
 * AccessDenied and the stack rolls back.
 */
beforeAll(() => {
  const srcBundled = path.join(__dirname, '../src/cloudfront/lambda-bundled');
  const libBundled = path.join(__dirname, '../lib/cloudfront/lambda-bundled');
  if (!fs.existsSync(srcBundled) && fs.existsSync(libBundled)) {
    fs.symlinkSync(libBundled, srcBundled, 'dir');
  }
});

function template(): Template {
  const app = new core.App();
  const stack = new core.Stack(app, 'CopySecretGrants', { env: { account: '123456789012', region: 'ap-southeast-2' } });
  new AuthInfrastructure(stack, 'Auth', {
    zoneName: 'admin.example.com',
    tenantId: 'tenant-123',
    clientId: 'client-abc',
    oauth2CallbackRoleName: 'oauth2-callback-role',
    appSpec: { name: 'admin' },
  } as any);
  return Template.fromStack(stack);
}

/** The KVS actions granted to the role of the function whose code is the hmacSecret handler. */
function copySecretKvsActions(t: Template): string[] {
  const resources = t.toJSON().Resources as Record<string, any>;
  const copyFnId = Object.entries(resources).find(
    ([id, r]) => r.Type === 'AWS::Lambda::Function' && /CopySecret/.test(id),
  )?.[0];
  expect(copyFnId).toBeDefined();
  const roleRef = JSON.stringify(resources[copyFnId!].Properties.Role);
  const roleId = Object.keys(resources).find((id) => roleRef.includes(`"${id}"`));
  expect(roleId).toBeDefined();
  return Object.values(resources)
    .filter((r) => r.Type === 'AWS::IAM::Policy' && JSON.stringify(r.Properties.Roles).includes(`"${roleId}"`))
    .flatMap((p) => p.Properties.PolicyDocument.Statement)
    .flatMap((st: any) => (Array.isArray(st.Action) ? st.Action : [st.Action]))
    .filter((a: string) => a.startsWith('cloudfront-keyvaluestore:'));
}

describe('copy-secret Lambda KVS permissions', () => {
  test('allows GetKey, PutKey and DescribeKeyValueStore, the three calls the handler makes', () => {
    const actions = copySecretKvsActions(template());
    expect(actions).toEqual(expect.arrayContaining([
      'cloudfront-keyvaluestore:GetKey',
      'cloudfront-keyvaluestore:PutKey',
      'cloudfront-keyvaluestore:DescribeKeyValueStore',
    ]));
  });

  test('the handler still calls get_key, so the grant is needed', () => {
    const handler = fs.readFileSync(path.join(__dirname, '../src/cloudfront/lambda/hmacSecret/index.py'), 'utf8');
    expect(handler).toMatch(/get_key\(/);
  });
});
