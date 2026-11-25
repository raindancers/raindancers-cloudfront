import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_ec2 as ec2,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_ssm as ssm,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

/**
 * Props for {@link HookRelay}.
 */
export interface HookRelayProps {
  /** The VPC the relay runs in. The hook must be reachable from it on {@link hookUrl}. */
  readonly vpc: ec2.IVpc;
  /** Subnets for the relay. They need a route to the regional STS endpoint (NAT or an STS VPC endpoint). @default the VPC's private subnets with egress */
  readonly vpcSubnets?: ec2.SubnetSelection;
  /**
   * Security groups for the relay. The hook's own security group must allow the relay's group in.
   * @default one new group with outbound traffic allowed
   */
  readonly securityGroups?: ec2.ISecurityGroup[];
  /**
   * The private URL of the identity-linking hook, for example
   * `http://medusa-api.hermes.internal:9000/hooks/identity-link`.
   */
  readonly hookUrl: string;
  /**
   * The audience the hook expects in the web identity token (`aud`). The relay's role may only
   * request tokens for this audience.
   */
  readonly audience: string;
  /**
   * Region of the regional STS endpoint used for `GetWebIdentityToken`. It is not on the global
   * endpoint.
   * @default the region of the stack
   */
  readonly stsRegion?: string;
  /**
   * Warm instances to keep, through a published alias. Off unless set. When set, the edge function
   * must invoke {@link HookRelay.invokeTargetArn} (the alias), which is what this construct exposes.
   * @default undefined (no provisioned concurrency, no alias)
   */
  readonly provisionedConcurrency?: number;
  /** Timeout of the call from the relay to the hook, seconds. @default 2.5 */
  readonly hookTimeoutSeconds?: number;
  /** Function timeout, seconds. It must exceed {@link hookTimeoutSeconds} plus a token call. @default 10 */
  readonly timeout?: core.Duration;
  /** Memory, MB. @default 256 */
  readonly memorySize?: number;
  /**
   * Write {@link HookRelay.invokeTargetArn} to this SSM parameter name, so a stack in another region
   * can read it (the edge stack is in us-east-1, the relay is not). No cross-region stack
   * references are used.
   * @default undefined (nothing is written)
   */
  readonly invokeTargetArnSsmParameter?: string;
}

/**
 * A Lambda in a VPC that carries the session Lambda@Edge's identity-link call to a private hook.
 *
 * Lambda@Edge cannot join a VPC, so it cannot reach a private service. It can invoke a regular
 * Lambda with `lambda:Invoke`, which is this function. The relay calls the hook's private URL and
 * proves who it is with a short-lived web identity token from AWS STS (`GetWebIdentityToken`, IAM
 * outbound identity federation): the hook checks the token's signature against the issuer's
 * public keys, plus the issuer, the audience and the relay's role ARN. There is no shared secret.
 *
 * The function has no function URL and no public endpoint, and nothing here opens an inbound path.
 * Outbound identity federation must be enabled once per account
 * (`aws iam enable-outbound-web-identity-federation`); the issuer URL it returns is what the hook
 * trusts.
 *
 * Pass {@link invokeTargetArn} (and the function's region) to `CognitoCustomUiAuth` as
 * `identityLinkingHookRelayArn` and `identityLinkingHookRelayRegion`.
 *
 * Optional and independent: a stack that does not create this construct is unchanged.
 */
export class HookRelay extends constructs.Construct {
  /** The relay function. */
  public readonly function: lambda.Function;
  /** The role the hook should expect in the token's `principal_id` claim. */
  public readonly role: iam.IRole;
  /**
   * What a caller invokes: the alias ARN when {@link HookRelayProps.provisionedConcurrency} is set,
   * else the function ARN. Grant `lambda:InvokeFunction` on exactly this.
   */
  public readonly invokeTargetArn: string;
  /** The security group made for the relay, when none was passed in. */
  public readonly securityGroup?: ec2.ISecurityGroup;

  constructor(scope: constructs.Construct, id: string, props: HookRelayProps) {
    super(scope, id);

    if (props.provisionedConcurrency !== undefined &&
      (!Number.isInteger(props.provisionedConcurrency) || props.provisionedConcurrency < 1)) {
      throw new Error('provisionedConcurrency must be a whole number of 1 or more');
    }
    const hookTimeoutSeconds = props.hookTimeoutSeconds ?? 2.5;
    const timeout = props.timeout ?? core.Duration.seconds(10);
    if (timeout.toSeconds() <= hookTimeoutSeconds) {
      throw new Error('timeout must be longer than hookTimeoutSeconds');
    }
    const stsRegion = props.stsRegion ?? core.Stack.of(this).region;
    if (core.Token.isUnresolved(stsRegion)) {
      throw new Error('stsRegion is required when the stack region is not known at synth time');
    }

    let securityGroups = props.securityGroups;
    if (!securityGroups) {
      const sg = new ec2.SecurityGroup(this, 'SecurityGroup', {
        vpc: props.vpc,
        description: 'Hook relay: outbound to the hook and to STS',
        allowAllOutbound: true,
      });
      this.securityGroup = sg;
      securityGroups = [sg];
    }

    this.function = new lambda.Function(this, 'Function', {
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'index.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/hook-relay'), {
        exclude: ['tests', 'tests/*', '__pycache__', '*.pyc'],
      }),
      timeout,
      memorySize: props.memorySize ?? 256,
      vpc: props.vpc,
      vpcSubnets: props.vpcSubnets ?? { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups,
      description: 'Carries the identity-link call from Lambda@Edge to a private hook',
      environment: {
        HOOK_URL: props.hookUrl,
        HOOK_AUDIENCE: props.audience,
        STS_REGION: stsRegion,
        HOOK_TIMEOUT_SECONDS: String(hookTimeoutSeconds),
      },
    });
    this.role = this.function.role!;

    // Only the audience of this hook, and only the 5 minute tokens the relay asks for. The shape
    // is the policy in the AWS getting-started guide for outbound identity federation.
    this.function.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sts:GetWebIdentityToken'],
      resources: ['*'],
      conditions: {
        'ForAllValues:StringEquals': { 'sts:IdentityTokenAudience': props.audience },
        'Null': { 'sts:IdentityTokenAudience': 'false' },
        'NumericLessThanEquals': { 'sts:DurationSeconds': 300 },
      },
    }));

    if (props.provisionedConcurrency !== undefined) {
      const alias = this.function.addAlias('live', {
        provisionedConcurrentExecutions: props.provisionedConcurrency,
      });
      this.invokeTargetArn = alias.functionArn;
    } else {
      this.invokeTargetArn = this.function.functionArn;
    }

    if (props.invokeTargetArnSsmParameter) {
      new ssm.StringParameter(this, 'InvokeTargetArnParameter', {
        parameterName: props.invokeTargetArnSsmParameter,
        stringValue: this.invokeTargetArn,
        description: 'ARN the session Lambda@Edge invokes to reach the identity-link hook',
      });
    }
  }
}
