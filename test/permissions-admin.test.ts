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

function synth(): { template: Template; stack: core.Stack } {
  const app = new core.App();
  const stack = new core.Stack(app, 'PAStack', { env: { account: '123456789012', region: 'eu-west-2' } });

  const bucket = new s3.Bucket(stack, 'AssetBucket');
  const distribution = new cloudfront.Distribution(stack, 'Dist', {
    defaultBehavior: { origin: origins.S3BucketOrigin.withOriginAccessControl(bucket) },
  });

  new PermissionsAdmin(stack, 'Admin', {
    domainName: 'shop.example.com',
    distribution,
    assetBucket: bucket,
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
      sessionHmacSecretArn: 'arn:aws:secretsmanager:eu-west-2:123456789012:secret:sess-abc',
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

  test('grants the Lambda access to each injected table (R16)', () => {
    const t = synth().template;
    // The management role has DynamoDB item/query actions in some policy.
    const policies = t.findResources('AWS::IAM::Policy');
    const anyDdb = Object.values(policies).some((p: any) =>
      JSON.stringify(p.Properties.PolicyDocument).includes('dynamodb:PutItem'));
    expect(anyDdb).toBe(true);
    // And a GetSecretValue grant on the session secret.
    const anySecret = Object.values(policies).some((p: any) =>
      JSON.stringify(p.Properties.PolicyDocument).includes('secretsmanager:GetSecretValue'));
    expect(anySecret).toBe(true);
  });

  test('no synthesized resource name or prop contains a consumer domain term (R7.3)', () => {
    const json = JSON.stringify(synth().template.toJSON());
    expect(json.toLowerCase()).not.toContain('brand');
    expect(json.toLowerCase()).not.toContain('subject');
  });
});
