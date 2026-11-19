import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_wafv2 as wafv2,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

/** The path a campaign link redirect is served on, unless the shop sets another. */
export const DEFAULT_LINK_PREFIX = '/r';

/**
 * The header the shop's origin sets so the redirector knows which shop the click came
 * from. A visitor cannot set an origin header, and CloudFront forwards no viewer
 * headers to the function (no origin request policy), so the function can trust it.
 */
export const LINK_HOST_HEADER = 'x-horton-link-host';

/**
 * The header the web ACL rules from {@link campaignLinkWafRules} insert on a request
 * Bot Control labelled. AWS WAF puts `x-amzn-waf-` in front of the name, so the
 * function sees `x-amzn-waf-link-bot`.
 */
export const LINK_BOT_HEADER = 'link-bot';

// One path piece: a "/", then lower case letters, digits or dashes. Keep in step with
// horton's brand settings (a prefix must not look like a ten character link code).
const PREFIX_RE = /^\/[a-z0-9-]{1,32}$/;
const CODE_SHAPE_RE = /^[A-Z0-9]{10}$/;
const FUNCTION_URL_DOMAIN_RE = /^[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws$/;
const HOST_RE = /^(?=.{1,240}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** Throws when a prefix is not one lower case path piece, or looks like a link code. */
export function validateLinkPrefix(prefix: string): void {
  if (!PREFIX_RE.test(prefix) || CODE_SHAPE_RE.test(prefix.slice(1))) {
    throw new Error(
      `prefix '${prefix}' must be one path piece like '/r': a "/" then lower case letters, digits or dashes, at most 32 characters, and not ten digits`,
    );
  }
}

export interface CampaignLinkRedirectProps {
  /**
   * The shop's distribution: a plain `cloudfront.Distribution`, or the `.distribution` of
   * `SecuredCloudFront`. It must be made in the same stack as this construct, because a
   * CDK distribution can only be changed where it is built.
   */
  readonly distribution: cloudfront.Distribution;
  /** The brand's redirector function URL domain, e.g. `abc123.lambda-url.ap-southeast-2.on.aws`. */
  readonly functionUrlDomain: string;
  /** The host the shop answers on. Sent to the function as `x-horton-link-host`. */
  readonly shopHost: string;
  /** One path piece. Default `/r`. */
  readonly prefix?: string;
}

/** A custom origin that signs its requests with an origin access control. */
class FunctionUrlOacOrigin extends origins.HttpOrigin {
  constructor(domainName: string, private readonly oacId: string, props: origins.HttpOriginProps) {
    super(domainName, props);
  }

  public bind(scope: constructs.Construct, options: cloudfront.OriginBindOptions): cloudfront.OriginBindConfig {
    const config = super.bind(scope, options);
    return {
      ...config,
      originProperty: { ...config.originProperty!, originAccessControlId: this.oacId },
    };
  }
}

/**
 * Sends `<prefix>/*` on a shop's CloudFront to horton's campaign link redirector
 * (spec utm-link-redirect in horton, design section 10).
 *
 * A link in a campaign email is `https://<shop>/r/<code>`. This adds, to the shop's own
 * distribution:
 *
 *  - an origin for the brand's Lambda function URL (HTTPS only), with an origin access
 *    control of type `lambda` that signs every request, and the origin header
 *    `x-horton-link-host: <shopHost>`;
 *  - a behaviour for `<prefix>/*`: caching off, **no origin request policy** (so no
 *    cookies, no query string and no visitor headers reach horton), `GET` and `HEAD`
 *    only, HTTP redirected to HTTPS, no function association and no login extension.
 *
 * It does not give the function permission to be called: the function is horton's, in
 * another account, and horton does that from the list of distribution ARNs. Pass
 * {@link distributionArn} to horton. It does not touch `robots.txt` or the sitemap (add
 * `Disallow: <prefix>/` yourself), and it does not change a web ACL (see
 * {@link campaignLinkWafRules}).
 *
 * Horton never edits a shop's CloudFront: an origin is a list item inside the
 * distribution, so an edit made from outside would be lost on the next deploy.
 */
export class CampaignLinkRedirect extends constructs.Construct {
  /** The distribution's ARN, for horton's list of allowed distributions. */
  public readonly distributionArn: string;
  /** The path pattern of the behaviour this adds, e.g. `/r/*`. */
  public readonly pathPattern: string;
  /** The id of the origin access control this makes. */
  public readonly originAccessControlId: string;

  constructor(scope: constructs.Construct, id: string, props: CampaignLinkRedirectProps) {
    super(scope, id);

    const prefix = props.prefix ?? DEFAULT_LINK_PREFIX;
    validateLinkPrefix(prefix);
    if (!FUNCTION_URL_DOMAIN_RE.test(props.functionUrlDomain)) {
      throw new Error(
        `functionUrlDomain '${props.functionUrlDomain}' must be a Lambda function URL domain like 'abc123.lambda-url.ap-southeast-2.on.aws' (no https://, no path)`,
      );
    }
    if (!HOST_RE.test(props.shopHost)) {
      throw new Error(`shopHost '${props.shopHost}' must be a lower case DNS name like 'shop.example.com'`);
    }
    const stack = core.Stack.of(this);
    if (core.Stack.of(props.distribution) !== stack) {
      throw new Error('CampaignLinkRedirect must be made in the same stack as its distribution');
    }

    const oac = new cloudfront.CfnOriginAccessControl(this, 'Oac', {
      originAccessControlConfig: {
        name: `${core.Names.uniqueResourceName(this, { maxLength: 55, separator: '-' })}-link`,
        description: 'Signs requests to the horton campaign link redirector function URL',
        originAccessControlOriginType: 'lambda',
        signingBehavior: 'always',
        signingProtocol: 'sigv4',
      },
    });

    const origin = new FunctionUrlOacOrigin(props.functionUrlDomain, oac.attrId, {
      protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
      customHeaders: { [LINK_HOST_HEADER]: props.shopHost },
    });

    this.pathPattern = `${prefix}/*`;
    props.distribution.addBehavior(this.pathPattern, origin, {
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      // Deliberately none: nothing of the visitor is passed on.
      originRequestPolicy: undefined,
    });

    this.originAccessControlId = oac.attrId;
    this.distributionArn = stack.formatArn({
      service: 'cloudfront',
      region: '',
      resource: 'distribution',
      resourceName: props.distribution.distributionId,
    });
  }
}

export interface CampaignLinkWafRulesProps {
  /** The same prefix as the redirect. Default `/r`. */
  readonly prefix?: string;
  /**
   * The priority of the first rule. The three rules take consecutive priorities, so the
   * ACL's other rules must leave `startPriority` to `startPriority + 2` free.
   */
  readonly startPriority: number;
  /** A prefix for the rule and metric names. Default `CampaignLink`. */
  readonly namePrefix?: string;
  /** Requests from one address in the window before the rate rule acts. Default 10,000. */
  readonly rateLimit?: number;
  /** `count` (default) only counts. `block` blocks an address past the limit. */
  readonly rateLimitAction?: 'count' | 'block';
}

/**
 * The web ACL rules for the redirect path (spec design section 14). They are for the
 * shop's stack to add to its own ACL, because an ACL is a separate resource that this
 * construct does not own.
 *
 *  1. A rate rule per IP address on `<prefix>/*`, to protect the function. The limit is
 *     high enough that a mail scanner opening many links from one address is not caught,
 *     and the rule counts by default.
 *  2. Bot Control (common level) on `<prefix>/*`, in count mode: it only labels.
 *  3. A rule that, for a labelled request on `<prefix>/*`, inserts the header
 *     `link-bot: labelled` (seen by the function as `x-amzn-waf-link-bot`), so a click by
 *     a mail scanner can be told from a person's. Nothing is blocked because of a label.
 */
export function campaignLinkWafRules(props: CampaignLinkWafRulesProps): wafv2.CfnWebACL.RuleProperty[] {
  const prefix = props.prefix ?? DEFAULT_LINK_PREFIX;
  validateLinkPrefix(prefix);
  const name = props.namePrefix ?? 'CampaignLink';
  const limit = props.rateLimit ?? 10000;
  if (!Number.isInteger(limit) || limit < 10) {
    throw new Error('rateLimit must be a whole number of at least 10 (the smallest AWS WAF allows)');
  }
  if (!Number.isInteger(props.startPriority) || props.startPriority < 0) {
    throw new Error('startPriority must be a whole number of at least 0');
  }
  const visibility = (metric: string): wafv2.CfnWebACL.VisibilityConfigProperty => ({
    cloudWatchMetricsEnabled: true,
    sampledRequestsEnabled: true,
    metricName: metric,
  });
  const onPath: wafv2.CfnWebACL.StatementProperty = {
    byteMatchStatement: {
      fieldToMatch: { uriPath: {} },
      positionalConstraint: 'STARTS_WITH',
      searchString: `${prefix}/`,
      textTransformations: [{ priority: 0, type: 'NONE' }],
    },
  };
  return [
    {
      name: `${name}RateLimit`,
      priority: props.startPriority,
      action: props.rateLimitAction === 'block' ? { block: {} } : { count: {} },
      statement: {
        rateBasedStatement: {
          limit,
          aggregateKeyType: 'IP',
          evaluationWindowSec: 300,
          scopeDownStatement: onPath,
        },
      },
      visibilityConfig: visibility(`${name}RateLimit`),
    },
    {
      name: `${name}BotControl`,
      priority: props.startPriority + 1,
      // Count: Bot Control only labels here; the next rule reads the label.
      overrideAction: { count: {} },
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesBotControlRuleSet',
          managedRuleGroupConfigs: [{ awsManagedRulesBotControlRuleSet: { inspectionLevel: 'COMMON' } }],
          scopeDownStatement: onPath,
        },
      },
      visibilityConfig: visibility(`${name}BotControl`),
    },
    {
      name: `${name}TagBots`,
      priority: props.startPriority + 2,
      action: { count: { customRequestHandling: { insertHeaders: [{ name: LINK_BOT_HEADER, value: 'labelled' }] } } },
      statement: {
        andStatement: {
          statements: [
            { labelMatchStatement: { scope: 'NAMESPACE', key: 'awswaf:managed:aws:bot-control:bot:' } },
            onPath,
          ],
        },
      },
      visibilityConfig: visibility(`${name}TagBots`),
    },
  ];
}
