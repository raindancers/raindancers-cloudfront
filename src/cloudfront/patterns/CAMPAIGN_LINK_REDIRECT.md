# Campaign link redirect

For a shop that sends campaign email through horton. A link in a campaign email is
`https://<your shop>/r/<code>`. Horton's redirector answers 302 to the original link with
GA4 campaign tags added, so the visit shows up in GA4 with its campaign.

`CampaignLinkRedirect` adds the shop's side of that to its own CloudFront distribution:

- an origin for the brand's redirector (a Lambda function URL), signed with an origin
  access control, with the header `x-horton-link-host: <shop host>`;
- a behaviour for `/r/*`: caching off, no origin request policy (no cookies, query string
  or visitor headers reach horton), `GET` and `HEAD` only, no login extension.

Horton never edits a shop's CloudFront. The shop's own stack calls this, so the change
survives every deploy.

## Use

```ts
import { CampaignLinkRedirect } from 'raindancers-cloudfront';

const redirect = new CampaignLinkRedirect(this, 'CampaignLinks', {
  distribution,                        // a cloudfront.Distribution in this stack, or SecuredCloudFront's .distribution
  functionUrlDomain: 'abc123xyz.lambda-url.ap-southeast-2.on.aws', // shown on the brand page in horton
  shopHost: 'shop.example.com',
  // prefix: '/r',                     // one path piece; must match the setting in horton
});

// Give this to horton: the brand page, "Shop's CloudFront distribution ARN".
new CfnOutput(this, 'LinkRedirectDistributionArn', { value: redirect.distributionArn });
```

The values to pass are on the brand's edit page in horton, in "What each shop's team must
set up". Until the shop's stack is deployed and horton's check passes, horton sends direct
links with the tags, so no link is ever dead.

## What the shop still does

- **Horton's side of the permission.** Horton lets this distribution call the function from
  the distribution ARN saved on the brand page. This construct cannot do that: the function
  is in another account.
- **`robots.txt`.** Add `Disallow: /r/` (your prefix) and keep `/r/` out of the sitemap.
- **Web ACL.** The ACL is a separate resource this construct does not own. Add the rules
  from `campaignLinkWafRules` to it:

```ts
import { campaignLinkWafRules } from 'raindancers-cloudfront';

new wafv2.CfnWebACL(this, 'Acl', {
  // ...
  rules: [...otherRules, ...campaignLinkWafRules({ startPriority: 50 })],
});
```

  It adds a rate rule per IP on `/r/*` (10,000 in five minutes, counting only by default),
  Bot Control at the common level (count mode, labels only), and a rule that inserts the
  header `x-amzn-waf-link-bot` on a labelled request, so horton can tell a mail scanner's
  click from a person's. Nothing is blocked because of a label. Rule priorities
  `startPriority` to `startPriority + 2` must be free. Whether your plan allows Bot Control
  and the extra rules is for you to check.
- **Nothing on the shop's own pages may link to `/r/...`.**
