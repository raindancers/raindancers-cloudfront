import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_wafv2 as wafv2,
} from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import {
  CampaignLinkRedirect,
  DEFAULT_LINK_PREFIX,
  LINK_BOT_HEADER,
  LINK_HOST_HEADER,
  campaignLinkWafRules,
  validateLinkPrefix,
} from '../src/cloudfront/patterns/campaignLinkRedirect';

/**
 * The shop side of horton's campaign links (spec utm-link-redirect, design section 10):
 * one origin, one behaviour, an origin access control, and nothing of the visitor
 * passed to the function.
 */
const FUNCTION_URL = 'abc123xyz.lambda-url.ap-southeast-2.on.aws';

function build(opts: Partial<{ prefix: string; extraBehaviors: boolean; shopHost: string; domain: string }> = {}) {
  const app = new core.App();
  const stack = new core.Stack(app, 'Shop', { env: { account: '433041915837', region: 'us-east-1' } });
  const distribution = new cloudfront.Distribution(stack, 'Dist', {
    defaultBehavior: { origin: new origins.HttpOrigin('origin.shop.test') },
    additionalBehaviors: opts.extraBehaviors
      ? { '/wp-admin/*': { origin: new origins.HttpOrigin('origin.shop.test') } }
      : undefined,
  });
  const redirect = new CampaignLinkRedirect(stack, 'LinkRedirect', {
    distribution,
    functionUrlDomain: opts.domain ?? FUNCTION_URL,
    shopHost: opts.shopHost ?? 'shop.test',
    prefix: opts.prefix,
  });
  return { stack, distribution, redirect, template: Template.fromStack(stack) };
}

const dist = (t: Template): any => (Object.values(t.findResources('AWS::CloudFront::Distribution'))[0] as any).Properties.DistributionConfig;
const linkOrigin = (t: Template): any => dist(t).Origins.find((o: any) => o.DomainName === FUNCTION_URL);
const linkBehavior = (t: Template, pattern = '/r/*'): any => dist(t).CacheBehaviors.find((b: any) => b.PathPattern === pattern);

describe('CampaignLinkRedirect', () => {
  it('adds an origin for the function URL, HTTPS only, with the shop host as an origin header', () => {
    const origin = linkOrigin(build().template);
    expect(origin.CustomOriginConfig.OriginProtocolPolicy).toBe('https-only');
    expect(origin.OriginCustomHeaders).toEqual([{ HeaderName: LINK_HOST_HEADER, HeaderValue: 'shop.test' }]);
    expect(LINK_HOST_HEADER).toBe('x-horton-link-host');
  });

  it('makes an origin access control for a Lambda origin that always signs with SigV4', () => {
    const t = build().template;
    const oacs = Object.values(t.findResources('AWS::CloudFront::OriginAccessControl')) as any[];
    expect(oacs).toHaveLength(1);
    expect(oacs[0].Properties.OriginAccessControlConfig).toMatchObject({
      OriginAccessControlOriginType: 'lambda',
      SigningBehavior: 'always',
      SigningProtocol: 'sigv4',
    });
    expect(oacs[0].Properties.OriginAccessControlConfig.Name.length).toBeLessThanOrEqual(64);
  });

  it('puts the access control on the redirector origin and on no other origin, even when it is not first', () => {
    const t = build({ extraBehaviors: true }).template;
    const origins_ = dist(t).Origins as any[];
    expect(origins_.length).toBeGreaterThanOrEqual(2);
    const withOac = origins_.filter((o) => o.OriginAccessControlId !== undefined);
    expect(withOac).toHaveLength(1);
    expect(withOac[0].DomainName).toBe(FUNCTION_URL);
    expect(JSON.stringify(withOac[0].OriginAccessControlId)).toMatch(/Oac/);
  });

  it('adds a behaviour for /r/* with caching off, GET and HEAD only, and HTTP sent to HTTPS', () => {
    const b = linkBehavior(build().template);
    expect(b.AllowedMethods).toEqual(['GET', 'HEAD']);
    expect(b.ViewerProtocolPolicy).toBe('redirect-to-https');
    // the managed CachingDisabled policy
    expect(b.CachePolicyId).toBe('4135ea2d-6df8-44a3-9df3-4b5a84be39ad');
  });

  it('passes nothing of the visitor on: no origin request policy, no function, no login', () => {
    const b = linkBehavior(build().template);
    expect(b.OriginRequestPolicyId).toBeUndefined();
    expect(b.FunctionAssociations).toBeUndefined();
    expect(b.LambdaFunctionAssociations).toBeUndefined();
    expect(b.TrustedKeyGroups).toBeUndefined();
    expect(b.TrustedSigners).toBeUndefined();
    expect(b.FieldLevelEncryptionId).toBeUndefined();
  });

  it('points the behaviour at the redirector origin', () => {
    const t = build().template;
    const b = linkBehavior(t);
    const origin = dist(t).Origins.find((o: any) => o.DomainName === FUNCTION_URL);
    expect(b.TargetOriginId).toBe(origin.Id);
    expect(dist(t).DefaultCacheBehavior.TargetOriginId).not.toBe(origin.Id);
  });

  it('leaves the shop\'s own behaviours and origins as they were', () => {
    const t = build({ extraBehaviors: true }).template;
    expect(dist(t).CacheBehaviors.map((x: any) => x.PathPattern).sort()).toEqual(['/r/*', '/wp-admin/*']);
    expect(dist(t).Origins.filter((o: any) => o.DomainName === 'origin.shop.test').length).toBeGreaterThanOrEqual(1);
  });

  it('can use another path', () => {
    const { template, redirect } = build({ prefix: '/go' });
    expect(linkBehavior(template, '/go/*')).toBeDefined();
    expect(redirect.pathPattern).toBe('/go/*');
    expect(DEFAULT_LINK_PREFIX).toBe('/r');
  });

  it('exposes the distribution ARN horton needs, and the access control id', () => {
    const { redirect, stack, distribution } = build();
    const resolved = JSON.stringify(stack.resolve(redirect.distributionArn));
    expect(resolved).toContain('"Fn::Join"');
    expect(resolved).toContain(':cloudfront::433041915837:distribution/');
    expect(resolved).toContain(JSON.stringify({ Ref: stack.getLogicalId(distribution.node.defaultChild as cloudfront.CfnDistribution) }));
    expect(stack.resolve(redirect.originAccessControlId)).toHaveProperty('Fn::GetAtt');
  });

  it('works on the distribution of a SecuredCloudFront-style construct, which is a plain Distribution', () => {
    // SecuredCloudFront exposes `.distribution`: one cloudfront.Distribution, the same type this takes.
    const { template } = build({ extraBehaviors: true });
    expect(linkBehavior(template)).toBeDefined();
  });

  it('does not add a function permission, a web ACL, a DNS record or anything else', () => {
    const t = build().template;
    const types = new Set(Object.values(t.toJSON().Resources).map((r: any) => r.Type));
    expect([...types].sort()).toEqual(['AWS::CloudFront::Distribution', 'AWS::CloudFront::OriginAccessControl']);
  });
});

describe('CampaignLinkRedirect refuses bad input', () => {
  it.each(['r', '/', '/R', '/a/b', '/r/', '/r r', `/${'a'.repeat(33)}`, '/1234567890', '//r', ''])(
    'rejects the prefix %j',
    (prefix) => {
      expect(() => build({ prefix })).toThrow(/prefix/);
    },
  );

  it('accepts a prefix that is nine digits or has letters', () => {
    expect(() => validateLinkPrefix('/123456789')).not.toThrow();
    expect(() => validateLinkPrefix('/12345678a0')).not.toThrow();
    expect(() => validateLinkPrefix('/r')).not.toThrow();
  });

  it.each(['https://abc.lambda-url.ap-southeast-2.on.aws', 'abc.lambda-url.ap-southeast-2.on.aws/', 'abc.example.com', 'ABC.lambda-url.ap-southeast-2.on.aws', ''])(
    'rejects the function URL domain %j',
    (domain) => {
      expect(() => build({ domain })).toThrow(/functionUrlDomain/);
    },
  );

  it.each(['Shop.Test', 'shop', 'https://shop.test', 'shop.test/path', 'a b.test', ''])('rejects the shop host %j', (shopHost) => {
    expect(() => build({ shopHost })).toThrow(/shopHost/);
  });

  it('refuses a distribution from another stack', () => {
    const app = new core.App();
    const a = new core.Stack(app, 'A');
    const b = new core.Stack(app, 'B');
    const distribution = new cloudfront.Distribution(a, 'Dist', { defaultBehavior: { origin: new origins.HttpOrigin('o.shop.test') } });
    expect(
      () => new CampaignLinkRedirect(b, 'LinkRedirect', { distribution, functionUrlDomain: FUNCTION_URL, shopHost: 'shop.test' }),
    ).toThrow(/same stack/);
  });
});

describe('campaignLinkWafRules', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rules: any[] = campaignLinkWafRules({ startPriority: 10 });

  it('gives three rules with consecutive priorities and unique names', () => {
    expect(rules.map((r) => r.priority)).toEqual([10, 11, 12]);
    expect(new Set(rules.map((r) => r.name)).size).toBe(3);
    expect(rules.map((r) => r.name)).toEqual(['CampaignLinkRateLimit', 'CampaignLinkBotControl', 'CampaignLinkTagBots']);
    for (const r of rules) {
      expect(r.visibilityConfig.metricName).toBe(r.name);
      expect(r.visibilityConfig.cloudWatchMetricsEnabled).toBe(true);
    }
  });

  it('counts the rate rule by default, per IP, in five minutes, on the link path only', () => {
    const [rate] = rules;
    expect(rate.action).toEqual({ count: {} });
    expect(rate.statement.rateBasedStatement).toMatchObject({ limit: 10000, aggregateKeyType: 'IP', evaluationWindowSec: 300 });
    expect(JSON.stringify(rate.statement.rateBasedStatement.scopeDownStatement)).toContain('/r/');
  });

  it('can block past the limit, and the limit can be set', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const [rate]: any[] = campaignLinkWafRules({ startPriority: 0, rateLimit: 500, rateLimitAction: 'block' });
    expect(rate.action).toEqual({ block: {} });
    expect(rate.statement.rateBasedStatement.limit).toBe(500);
  });

  it('only labels with Bot Control at the common level, on the link path', () => {
    const bot = rules[1];
    expect(bot.overrideAction).toEqual({ count: {} });
    expect(bot.action).toBeUndefined();
    const stmt = bot.statement.managedRuleGroupStatement;
    expect(stmt).toMatchObject({ vendorName: 'AWS', name: 'AWSManagedRulesBotControlRuleSet' });
    expect(stmt.managedRuleGroupConfigs).toEqual([{ awsManagedRulesBotControlRuleSet: { inspectionLevel: 'COMMON' } }]);
    expect(JSON.stringify(stmt.scopeDownStatement)).toContain('/r/');
  });

  it('inserts link-bot only for a labelled request on the link path, and blocks nothing', () => {
    const tag = rules[2];
    expect(tag.action).toEqual({ count: { customRequestHandling: { insertHeaders: [{ name: LINK_BOT_HEADER, value: 'labelled' }] } } });
    const parts = tag.statement.andStatement.statements;
    expect(parts).toHaveLength(2);
    expect(parts[0].labelMatchStatement).toEqual({ scope: 'NAMESPACE', key: 'awswaf:managed:aws:bot-control:bot:' });
    expect(JSON.stringify(parts[1])).toContain('/r/');
    for (const r of rules) expect(JSON.stringify(r.action ?? {})).not.toContain('block');
  });

  it('follows a custom prefix and name prefix', () => {
    const custom = campaignLinkWafRules({ startPriority: 5, prefix: '/go', namePrefix: 'Shop' });
    expect(custom.map((r) => r.name)).toEqual(['ShopRateLimit', 'ShopBotControl', 'ShopTagBots']);
    expect(JSON.stringify(custom)).toContain('/go/');
    expect(JSON.stringify(custom)).not.toContain('"/r/"');
  });

  it.each([[{ startPriority: -1 }], [{ startPriority: 1.5 }], [{ startPriority: 1, rateLimit: 9 }], [{ startPriority: 1, rateLimit: 1.5 }], [{ startPriority: 1, prefix: '/Bad' }]])(
    'rejects %j',
    (props) => {
      expect(() => campaignLinkWafRules(props as any)).toThrow();
    },
  );

  it('makes rules a real web ACL accepts', () => {
    const app = new core.App();
    const stack = new core.Stack(app, 'Acl', { env: { account: '433041915837', region: 'us-east-1' } });
    new wafv2.CfnWebACL(stack, 'Acl', {
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      visibilityConfig: { cloudWatchMetricsEnabled: true, sampledRequestsEnabled: true, metricName: 'acl' },
      rules: campaignLinkWafRules({ startPriority: 0 }),
    });
    const acl = Object.values(Template.fromStack(stack).findResources('AWS::WAFv2::WebACL'))[0] as any;
    expect(acl.Properties.Rules).toHaveLength(3);
  });
});
