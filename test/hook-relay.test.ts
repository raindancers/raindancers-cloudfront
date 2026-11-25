import * as core from 'aws-cdk-lib';
import { aws_ec2 as ec2 } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { HookRelay, HookRelayProps } from '../src/cloudfront/patterns/hookRelay';

const AUDIENCE = 'medusa-identity-hook';
const HOOK_URL = 'http://medusa-api.hermes.internal:9000/hooks/identity-link';

function synth(over: Partial<HookRelayProps> = {}): { template: Template; relay: HookRelay } {
  const app = new core.App();
  const stack = new core.Stack(app, 'RelayStack', { env: { account: '123456789012', region: 'eu-west-2' } });
  const vpc = new ec2.Vpc(stack, 'Vpc', { maxAzs: 2 });
  const relay = new HookRelay(stack, 'Relay', { vpc, hookUrl: HOOK_URL, audience: AUDIENCE, ...over });
  return { template: Template.fromStack(stack), relay };
}

function policyStatements(template: Template): any[] {
  return Object.values(template.findResources('AWS::IAM::Policy')).flatMap(
    (p: any) => p.Properties.PolicyDocument.Statement,
  );
}

describe('HookRelay', () => {
  test('is one Lambda in the VPC, with no function URL and no API', () => {
    const { template } = synth();
    template.resourceCountIs('AWS::Lambda::Function', 1);
    template.hasResourceProperties('AWS::Lambda::Function', {
      VpcConfig: Match.objectLike({ SubnetIds: Match.anyValue(), SecurityGroupIds: Match.anyValue() }),
    });
    template.resourceCountIs('AWS::Lambda::Url', 0);
    template.resourceCountIs('AWS::ApiGateway::RestApi', 0);
    template.resourceCountIs('AWS::ApiGatewayV2::Api', 0);
  });

  test('is placed in the private subnets with egress by default', () => {
    const { template } = synth();
    const fn: any = Object.values(template.findResources('AWS::Lambda::Function'))[0];
    const subnetRefs = JSON.stringify(fn.Properties.VpcConfig.SubnetIds);
    expect(subnetRefs).toContain('PrivateSubnet');
    expect(subnetRefs).not.toContain('PublicSubnet');
  });

  test('has no ingress rule and allows outbound traffic', () => {
    const { template } = synth();
    template.hasResourceProperties('AWS::EC2::SecurityGroup', {
      SecurityGroupIngress: Match.absent(),
    });
    template.resourceCountIs('AWS::EC2::SecurityGroupIngress', 0);
  });

  test('passes the hook URL, audience, STS region and timeout in the environment', () => {
    const { template } = synth();
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: {
          HOOK_URL: HOOK_URL,
          HOOK_AUDIENCE: AUDIENCE,
          STS_REGION: 'eu-west-2',
          HOOK_TIMEOUT_SECONDS: '2.5',
        },
      },
    });
  });

  test('may call GetWebIdentityToken only for its audience and for 300 seconds or less', () => {
    const { template } = synth();
    const sts = policyStatements(template).filter((s) => JSON.stringify(s.Action).includes('sts:GetWebIdentityToken'));
    expect(sts).toHaveLength(1);
    expect(sts[0].Effect).toBe('Allow');
    expect(sts[0].Action).toBe('sts:GetWebIdentityToken');
    expect(sts[0].Condition).toEqual({
      'ForAllValues:StringEquals': { 'sts:IdentityTokenAudience': AUDIENCE },
      'Null': { 'sts:IdentityTokenAudience': 'false' },
      'NumericLessThanEquals': { 'sts:DurationSeconds': 300 },
    });
  });

  test('has no provisioned concurrency and no alias by default', () => {
    const { template, relay } = synth();
    template.resourceCountIs('AWS::Lambda::Alias', 0);
    template.resourceCountIs('AWS::Lambda::Version', 0);
    expect(core.Stack.of(relay).resolve(relay.invokeTargetArn)).toEqual({
      'Fn::GetAtt': [expect.stringContaining('RelayFunction'), 'Arn'],
    });
  });

  test('with provisioned concurrency, publishes a version, an alias and the setting, and exposes the alias ARN', () => {
    const { template, relay } = synth({ provisionedConcurrency: 1 });
    template.resourceCountIs('AWS::Lambda::Version', 1);
    template.hasResourceProperties('AWS::Lambda::Alias', {
      Name: 'live',
      ProvisionedConcurrencyConfig: { ProvisionedConcurrentExecutions: 1 },
    });
    const resolved = JSON.stringify(core.Stack.of(relay).resolve(relay.invokeTargetArn));
    expect(resolved).toContain('RelayFunctionAliaslive');
    // The alias points at a published version of this function, so it is not replaced on update.
    template.hasResourceProperties('AWS::Lambda::Alias', {
      FunctionVersion: Match.anyValue(),
    });
  });

  test.each([0, -1, 1.5])('refuses provisionedConcurrency %p', (n) => {
    expect(() => synth({ provisionedConcurrency: n })).toThrow(/whole number of 1 or more/);
  });

  test('refuses a function timeout that is not longer than the hook timeout', () => {
    expect(() => synth({ hookTimeoutSeconds: 10, timeout: core.Duration.seconds(10) })).toThrow(/longer than hookTimeoutSeconds/);
  });

  test('writes the invoke ARN to SSM only when asked', () => {
    synth().template.resourceCountIs('AWS::SSM::Parameter', 0);
    const { template } = synth({ invokeTargetArnSsmParameter: '/hook-relay/dev/invokeTargetArn' });
    template.hasResourceProperties('AWS::SSM::Parameter', { Name: '/hook-relay/dev/invokeTargetArn', Type: 'String' });
  });

  test('uses a security group that was passed in, and makes none of its own', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'S', { env: { account: '123456789012', region: 'eu-west-2' } });
    const vpc = new ec2.Vpc(stack, 'Vpc', { maxAzs: 2 });
    const sg = new ec2.SecurityGroup(stack, 'Mine', { vpc });
    const relay = new HookRelay(stack, 'Relay', { vpc, hookUrl: HOOK_URL, audience: AUDIENCE, securityGroups: [sg] });
    expect(relay.securityGroup).toBeUndefined();
    Template.fromStack(stack).resourceCountIs('AWS::EC2::SecurityGroup', 1);
  });

  test('needs an explicit STS region when the stack region is not known', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'S');
    const vpc = new ec2.Vpc(stack, 'Vpc', { maxAzs: 2 });
    expect(() => new HookRelay(stack, 'Relay', { vpc, hookUrl: HOOK_URL, audience: AUDIENCE })).toThrow(/stsRegion is required/);
    expect(() => new HookRelay(stack, 'Relay2', { vpc, hookUrl: HOOK_URL, audience: AUDIENCE, stsRegion: 'eu-west-2' })).not.toThrow();
  });
});
