import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_dynamodb as dynamodb,
  aws_iam as iam,
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

  // Regression (horton S2): when the OIDC provider ARN is a TOKEN — the normal
  // case for a standalone deployment co-located with an AuthInfrastructure that
  // CREATES the provider in the same stack, so its ARN is a `Ref` — the trust
  // condition key must still be a concrete string. The old code Fn.split the ARN
  // to build `<host>:aud`, producing an Fn::Select TOKEN used as a MAP KEY, which
  // CloudFormation rejects ("used as the key in a map so must resolve to a
  // string"). The fix derives the host from the concrete `issuer` instead.
  function synthWithTokenProvider(ci: { issuer?: string; audience?: string; trustedSubject?: string }) {
    const app = new core.App();
    const stack = new core.Stack(app, 'TokStack', { env: { account: '123456789012', region: 'eu-west-2' } });
    // A REAL provider in this stack -> its ARN is a Ref token, not a literal.
    const provider = new iam.OpenIdConnectProvider(stack, 'Oidc', {
      url: 'https://admin.shop.example.com',
      clientIds: ['https://admin.shop.example.com'],
    });
    new PermissionsAdmin(stack, 'Admin', {
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
        jwksUri: 'https://admin.shop.example.com/.well-known/jwks.json',
        webIdentityOidcProviderArn: provider.openIdConnectProviderArn, // TOKEN
        ...ci,
      },
    });
    return Template.fromStack(stack);
  }

  test('synthesizes with a TOKENIZED provider ARN and keys the trust condition on the concrete issuer host', () => {
    const t = synthWithTokenProvider({
      issuer: 'https://admin.shop.example.com',
      audience: 'https://admin.shop.example.com',
    });
    const roles = t.findResources('AWS::IAM::Role');
    const mgmtRole = Object.values(roles).find((r: any) =>
      JSON.stringify(r.Properties.AssumeRolePolicyDocument).includes('sts:AssumeRoleWithWebIdentity'));
    expect(mgmtRole).toBeDefined();
    const doc = (mgmtRole as any).Properties.AssumeRolePolicyDocument;
    const cond = JSON.stringify(doc.Statement[0].Condition);
    // The condition KEY is the concrete issuer host (scheme stripped), not a token.
    expect(cond).toContain('admin.shop.example.com:aud');
    // The map key itself must be a plain string, never an Fn::Select/Fn::Join token.
    const condKeys = Object.keys(doc.Statement[0].Condition.StringEquals);
    expect(condKeys).toContain('admin.shop.example.com:aud');
  });

  test('keys :sub on the concrete issuer host too when trustedSubject is set', () => {
    const t = synthWithTokenProvider({
      issuer: 'https://admin.shop.example.com',
      trustedSubject: 'operator@shop.example.com',
    });
    const roles = t.findResources('AWS::IAM::Role');
    const mgmtRole = Object.values(roles).find((r: any) =>
      JSON.stringify(r.Properties.AssumeRolePolicyDocument).includes('sts:AssumeRoleWithWebIdentity'));
    const keys = Object.keys((mgmtRole as any).Properties.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals);
    expect(keys).toContain('admin.shop.example.com:sub');
  });

  test('requires issuer when audience or trustedSubject is set (it supplies the concrete condition host)', () => {
    expect(() => synthWithTokenProvider({ audience: 'https://admin.shop.example.com' }))
      .toThrow(/issuer is required/);
  });

  test('the management role Description is within IAM\'s allowed charset (no deploy-time 400)', () => {
    // REGRESSION GUARD: IAM validates a role Description server-side against
    // [\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]* and rejects anything
    // outside it with a 400 at CREATE time. CDK does NOT validate the charset
    // locally, so synth + every template assertion pass while the deploy fails.
    // The description previously contained an em-dash (U+2014, > U+00FF), which
    // broke the first stand-up of this stack. Assert the rendered Description
    // contains only IAM-legal characters.
    const t = synth().template;
    const roles = t.findResources('AWS::IAM::Role');
    const mgmtRole = Object.values(roles).find((r: any) =>
      JSON.stringify(r.Properties.AssumeRolePolicyDocument).includes('sts:AssumeRoleWithWebIdentity'),
    ) as any;
    const description: string = mgmtRole.Properties.Description;
    expect(description).toBeDefined();
    // IAM's own allowed-character pattern for a role description.
    expect(description).toMatch(/^[\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]*$/);
    // And specifically: no em-dash (the exact char that broke the deploy).
    expect(description).not.toContain('\u2014');
  });
});
