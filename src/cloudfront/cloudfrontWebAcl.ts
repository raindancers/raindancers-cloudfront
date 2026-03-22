import * as core from 'aws-cdk-lib';
import {
  aws_wafv2 as wafv2,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';
import { Country } from './countries';

export { Country, CountryCode } from './countries';

export type CountryName = keyof typeof Country;

/**
 * Path-specific rate limit configuration.
 */
export interface PathRateLimit {
  /** URI path pattern (e.g., '/oauth2/callback', '/api/auth/*') */
  readonly path: string;
  /** Rate limit for this path (requests per 5 minutes) */
  readonly rateLimit: number;
  /** Optional name for the rule (auto-generated if not provided) */
  readonly name?: string;
}

/**
 * Properties for CloudFrontWebAcl construct.
 */
export interface CloudFrontWebAclProps {
  /** Name for the Web ACL */
  readonly name?: string;
  /** Whether to enable AWS managed rules (default: true) */
  readonly enableManagedRules?: boolean;
  /** Custom rules to add to the Web ACL */
  readonly rules?: wafv2.CfnWebACL.RuleProperty[];
  /** Rate limit for requests per 5 minutes (default: 2000) */
  readonly rateLimit?: number;
  /** Path-specific rate limits (overrides default rateLimit for matching paths) */
  readonly pathRateLimits?: PathRateLimit[];
  /** Allow requests only from these countries (all others blocked) */
  readonly allowedCountries?: CountryName[];
  /** Block requests from these countries (all others allowed) */
  readonly blockedCountries?: CountryName[];
}

/**
 * Creates a WAF WebACL in us-east-1 for use with CloudFront.
 *
 * CloudFront requires WAF WebACLs to be in us-east-1 with CLOUDFRONT scope.
 * This construct uses a custom resource to create the WebACL in us-east-1
 * regardless of the stack's region.
 *
 * Provides sensible defaults with AWS managed rules for common threats.
 *
 * @example
 * ```typescript
 * const webAcl = new CloudFrontWebAcl(this, 'WebAcl', {
 *   name: 'MyCloudFrontWebAcl',
 *   rateLimit: 10000, // Default for all paths
 *   pathRateLimits: [
 *     { path: '/oauth2/callback', rateLimit: 100 },
 *     { path: '/oauth2/authorize', rateLimit: 100 },
 *     { path: '/api/auth', rateLimit: 500 },
 *   ],
 *   allowedCountries: ['UnitedStates', 'Canada', 'UnitedKingdom'],
 * });
 *
 * new cloudfront.Distribution(this, 'Distribution', {
 *   webAclId: webAcl.webAclArn,
 *   // ...
 * });
 * ```
 */
export class CloudFrontWebAcl extends constructs.Construct {
  /** The WebACL ARN */
  public readonly webAclArn: string;
  /** The WebACL ID */
  public readonly webAclId: string;

  private readonly webAcl: wafv2.CfnWebACL;

  constructor(scope: constructs.Construct, id: string, props: CloudFrontWebAclProps = {}) {
    super(scope, id);

    if (props.allowedCountries && props.blockedCountries) {
      throw new Error('Cannot specify both allowedCountries and blockedCountries');
    }

    const name = props.name || `${core.Stack.of(this).stackName}-cloudfront-waf`;
    const enableManagedRules = props.enableManagedRules ?? true;
    const rateLimit = props.rateLimit ?? 2000;
    const pathRateLimits = props.pathRateLimits ?? [];
    const allowedCountries = props.allowedCountries?.map(c => Country[c]) ?? [];
    const blockedCountries = props.blockedCountries?.map(c => Country[c]) ?? [];

    const rules = this.buildRules(enableManagedRules, rateLimit, pathRateLimits, allowedCountries, blockedCountries);

    this.webAcl = new wafv2.CfnWebACL(this, 'WebACL', {
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      rules: rules,
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: name,
      },
      name: name,
    });

    this.webAclArn = this.webAcl.attrArn;
    this.webAclId = this.webAcl.attrId;
  }

  private buildRules(
    enableManagedRules: boolean,
    rateLimit: number,
    pathRateLimits: PathRateLimit[],
    allowedCountries: string[],
    blockedCountries: string[],
  ): wafv2.CfnWebACL.RuleProperty[] {
    const rules: wafv2.CfnWebACL.RuleProperty[] = [];
    let priority = 0;

    if (allowedCountries.length > 0) {
      rules.push({
        name: 'GeoAllowRule',
        priority: priority++,
        statement: {
          notStatement: {
            statement: {
              geoMatchStatement: {
                countryCodes: allowedCountries,
              },
            },
          },
        },
        action: { block: {} },
        visibilityConfig: {
          sampledRequestsEnabled: true,
          cloudWatchMetricsEnabled: true,
          metricName: 'GeoAllowRule',
        },
      });
    }

    if (blockedCountries.length > 0) {
      rules.push({
        name: 'GeoBlockRule',
        priority: priority++,
        statement: {
          geoMatchStatement: {
            countryCodes: blockedCountries,
          },
        },
        action: { block: {} },
        visibilityConfig: {
          sampledRequestsEnabled: true,
          cloudWatchMetricsEnabled: true,
          metricName: 'GeoBlockRule',
        },
      });
    }

    pathRateLimits.forEach((pathLimit, idx) => {
      const ruleName = pathLimit.name || `PathRateLimit${idx}`;
      rules.push({
        name: ruleName,
        priority: priority++,
        statement: {
          rateBasedStatement: {
            limit: pathLimit.rateLimit,
            aggregateKeyType: 'IP',
            scopeDownStatement: {
              byteMatchStatement: {
                searchString: pathLimit.path,
                fieldToMatch: { uriPath: {} },
                textTransformations: [{ priority: 0, type: 'NONE' }],
                positionalConstraint: pathLimit.path.includes('*') ? 'CONTAINS' : 'STARTS_WITH',
              },
            },
          },
        },
        action: { block: {} },
        visibilityConfig: {
          sampledRequestsEnabled: true,
          cloudWatchMetricsEnabled: true,
          metricName: ruleName,
        },
      });
    });

    rules.push({
      name: 'RateLimitRule',
      priority: priority++,
      statement: {
        rateBasedStatement: {
          limit: rateLimit,
          aggregateKeyType: 'IP',
        },
      },
      action: { block: {} },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'RateLimitRule',
      },
    });

    if (enableManagedRules) {
      rules.push(
        {
          name: 'AWSManagedRulesCommonRuleSet',
          priority: priority++,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
            },
          },
          overrideAction: { none: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesCommonRuleSet',
          },
        },
        {
          name: 'AWSManagedRulesKnownBadInputsRuleSet',
          priority: priority++,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesKnownBadInputsRuleSet',
            },
          },
          overrideAction: { none: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesKnownBadInputsRuleSet',
          },
        },
        {
          name: 'AWSManagedRulesAmazonIpReputationList',
          priority: priority++,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesAmazonIpReputationList',
            },
          },
          overrideAction: { none: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesAmazonIpReputationList',
          },
        },
        {
          name: 'AWSManagedRulesAnonymousIpList',
          priority: priority++,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesAnonymousIpList',
            },
          },
          overrideAction: { none: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesAnonymousIpList',
          },
        },
      );
    }

    return rules;
  }
}
