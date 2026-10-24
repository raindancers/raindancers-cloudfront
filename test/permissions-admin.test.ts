import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_dynamodb as dynamodb,
  aws_s3 as s3,
} from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { PermissionsAdmin } from '../src/cloudfront/patterns/permissionsAdmin';

// Link pre-bundled lambda dir so asset bundling resolves during tests (same
// shim the other CDK tests use).
beforeAll(() => {
  const srcBundled = path.join(__dirname, '../src/cloudfront/lambda-bundled');
  const libBundled = path.join(__dirname, '../lib/cloudfront/lambda-bundled');
  if (!fs.existsSync(srcBundled) && fs.existsSync(libBundled)) {
    fs.symlinkSync(libBundled, srcBundled, 'dir');
  }
});

function table(stack: core.Stack, id: string): dynamodb.ITable {
  return new dynamodb.Table(stack, id, {
    partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
    sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  });
}

function synth(opts: { standalone?: boolean } = {}): { template: Template; stack: core.Stack } {
  const app = new core.App();
  const stack = new core.Stack(app, 'PAStack', { env: { account: '123456789012', region: 'eu-west-2' } });

  const bucket = new s3.Bucket(stack, 'AssetBucket');
  const distribution = new cloudfront.Distribution(stack, 'Dist', {
    defaultBehavior: { origin: origins.S3BucketOrigin.withOriginAccessControl(bucket) },
  });

  new PermissionsAdmin(stack, 'Admin', {
    domainName: 'shop.example.com',
    // Single-stack mode wires the distribution + bucket; standalone omits both
    // so the construct builds only the regional API half.
    ...(opts.standalone ? {} : { distribution, assetBucket: bucket }),
    pathPrefix: 'admin',
    catalogue: { permissions: [{ id: 'content.write', name: 'Write content' }] },
    predefinedRoles: [{ id: 'editor', name: 'Editor', permissionIds: ['content.write'], bit: 0 }],
    rightsActLockout: ['danger.superuser'],
    scopeDimension: { label: 'scope', source: { type: 'STATIC' as any, staticScopeIds: ['a', 'b'] }, estateLevelPermissionIds: [] },
    managementPermissions: {
      createRole: 'mgmt.role.create',
      deleteRole: 'mgmt.role.delete',
      listRoles: 'mgmt.role.list',
      createAssignment: 'mgmt.assign.create',
      deleteAssignment: 'mgmt.assign.delete',
      listAssignments: 'mgmt.assign.list',
    },
    roleTable: table(stack, 'RoleTable'),
    assignmentTable: table(stack, 'AssignmentTable'),
    bitRegistryTable: table(stack, 'BitRegistryTable'),
    callerIdentity: {
      jwksUri: 'https://admin.shop.example.com/.well-known/jwks.json',
      issuer: 'https://admin.shop.example.com',
      audience: 'https://admin.shop.example.com',
      webIdentityOidcProviderArn:
        'arn:aws:iam::123456789012:oidc-provider/admin.shop.example.com',
    },
  });

  return { template: Template.fromStack(stack), stack };
}

describe('PermissionsAdmin', () => {
  test('creates a regional HTTP API and a Python management Lambda', () => {
    const t = synth().template;
    t.resourceCountIs('AWS::ApiGatewayV2::Api', 1);
    t.hasResourceProperties('AWS::Lambda::Function', { Runtime: 'python3.12' });
  });

  test('serves the SPA + API under the path prefix on the injected distribution (R14.3)', () => {
    const t = synth().template;
    // A BucketDeployment (SPA) targets the injected bucket under admin/.
    t.hasResourceProperties('Custom::CDKBucketDeployment', {
      DestinationBucketKeyPrefix: 'admin/',
    });
    // The distribution carries /admin/api/* and /admin/* cache behaviours.
    const dists = t.findResources('AWS::CloudFront::Distribution');
    const dist = Object.values(dists)[0] as any;
    const patterns = (dist.Properties.DistributionConfig.CacheBehaviors || []).map((b: any) => b.PathPattern);
    expect(patterns).toContain('/admin/api/*');
    expect(patterns).toContain('/admin/*');
  });

  test('store access is via an assumed estate role, not standing Lambda grants (R16, two-token model)', () => {
    const t = synth().template;
    // A management role trusted by the consumer's OIDC provider via web identity.
    const roles = t.findResources('AWS::IAM::Role');
    const mgmtRole = Object.values(roles).find((r: any) =>
      JSON.stringify(r.Properties.AssumeRolePolicyDocument).includes('sts:AssumeRoleWithWebIdentity'));
    expect(mgmtRole).toBeDefined();
    expect(JSON.stringify((mgmtRole as any).Properties.AssumeRolePolicyDocument))
      .toContain('oidc-provider/admin.shop.example.com');

    // That role carries the DynamoDB authority-table grants.
    const policies = t.findResources('AWS::IAM::Policy');
    const anyDdb = Object.values(policies).some((p: any) =>
      JSON.stringify(p.Properties.PolicyDocument).includes('dynamodb:PutItem'));
    expect(anyDdb).toBe(true);

    // HMAC is edge-only: the management plane reads NO Secrets Manager secret.
    const anySecret = Object.values(policies).some((p: any) =>
      JSON.stringify(p.Properties.PolicyDocument).includes('secretsmanager:GetSecretValue'));
    expect(anySecret).toBe(false);
  });

  test('the management Lambda is configured for RS256/JWKS authN, not HMAC', () => {
    const t = synth().template;
    const fns = t.findResources('AWS::Lambda::Function');
    const env = Object.values(fns)
      .map((f: any) => f.Properties.Environment?.Variables ?? {})
      .find((v: any) => 'JWKS_URI' in v);
    expect(env).toBeDefined();
    expect(env.JWKS_URI).toBe('https://admin.shop.example.com/.well-known/jwks.json');
    expect(env.MANAGEMENT_ROLE_ARN).toBeDefined();
    expect('SESSION_HMAC_SECRET_ARN' in env).toBe(false);
  });

  test('no synthesized resource name or prop contains a consumer domain term (R7.3)', () => {
    const json = JSON.stringify(synth().template.toJSON());
    expect(json.toLowerCase()).not.toContain('brand');
    expect(json.toLowerCase()).not.toContain('subject');
  });

  test('standalone mode (no distribution) builds the regional API with no CloudFront wiring', () => {
    const t = synth({ standalone: true }).template;
    // The regional half still stands up.
    t.resourceCountIs('AWS::ApiGatewayV2::Api', 1);
    t.hasResourceProperties('AWS::Lambda::Function', { Runtime: 'python3.12' });
    // The assumed estate role + its DynamoDB grants are unchanged.
    const roles = t.findResources('AWS::IAM::Role');
    const mgmtRole = Object.values(roles).find((r: any) =>
      JSON.stringify(r.Properties.AssumeRolePolicyDocument).includes('sts:AssumeRoleWithWebIdentity'));
    expect(mgmtRole).toBeDefined();
    // The construct mounts NOTHING on CloudFront and deploys NO SPA — the
    // consumer owns both in the distribution's own stack.
    const dists = t.findResources('AWS::CloudFront::Distribution');
    const withBehaviors = Object.values(dists).some((d: any) =>
      (d.Properties.DistributionConfig.CacheBehaviors || []).length > 0);
    expect(withBehaviors).toBe(false);
    t.resourceCountIs('Custom::CDKBucketDeployment', 0);
  });

  test('supplying exactly one of distribution / assetBucket is a wiring error', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'Bad', { env: { account: '123456789012', region: 'eu-west-2' } });
    const bucket = new s3.Bucket(stack, 'B');
    const base = {
      domainName: 'shop.example.com',
      catalogue: { permissions: [{ id: 'content.write', name: 'Write content' }] },
      predefinedRoles: [{ id: 'editor', name: 'Editor', permissionIds: ['content.write'], bit: 0 }],
      rightsActLockout: ['danger.superuser'],
      scopeDimension: { label: 'scope', source: { type: 'STATIC' as any, staticScopeIds: ['a'] }, estateLevelPermissionIds: [] },
      managementPermissions: {
        createRole: 'm',
        deleteRole: 'm',
        listRoles: 'm',
        createAssignment: 'm',
        deleteAssignment: 'm',
        listAssignments: 'm',
      },
      roleTable: table(stack, 'R'),
      assignmentTable: table(stack, 'A'),
      bitRegistryTable: table(stack, 'Bit'),
      callerIdentity: {
        jwksUri: 'https://x/.well-known/jwks.json',
        webIdentityOidcProviderArn: 'arn:aws:iam::123456789012:oidc-provider/x',
      },
    } as any;
    // assetBucket without distribution -> throws.
    expect(() => new PermissionsAdmin(stack, 'Bad', { ...base, assetBucket: bucket }))
      .toThrow(/must be supplied together|both omitted/);
  });
});
