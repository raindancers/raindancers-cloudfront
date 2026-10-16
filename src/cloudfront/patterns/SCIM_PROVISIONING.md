# SCIM Provisioning Service

A generic, reusable SCIM 2.0 provisioning service construct. An identity provider
(Entra, Okta, Ping, ...) provisions users and groups into a construct-owned
DynamoDB table over SCIM 2.0; a consuming application reads that table locally
with a single `GetItem` to resolve an external id to `active` + a group-id list.

Implements horton **ADR-0003.5** (the first adopter), but is consumer- and
IdP-agnostic: everything is a prop.

## Usage

```ts
import { ScimProvisioningService, ScimAuthMode } from 'raindancers-cloudfront';

const scim = new ScimProvisioningService(this, 'AdminScim', {
  authMode: ScimAuthMode.OAUTH_CLIENT_CREDENTIALS, // default
  accessTokenValidity: Duration.hours(1),
  removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
});

// Adopt scim.functionUrl as a CloudFront origin in a downstream stack (WAF +
// origin-access lock live there; out of scope for this construct).
// Grant your consumer read on the store:
scim.table.grantReadData(myConsumerLambda);
// Hand the IdP: scim.tokenUrl and scim.scimUrl. The operator sets the client
// secret value (scim.clientSecretArn) out-of-band — it is created as a
// placeholder, never auto-generated.
```

### Auth modes

| Mode | Wire credential | Token endpoint | Stored secret |
|---|---|---|---|
| `OAUTH_CLIENT_CREDENTIALS` (default) | short-lived KMS-signed JWT | yes (self-hosted) | client secret (placeholder, set out-of-band) |
| `AWS_IAM` | SigV4 (Function URL) | no | none |
| `WIF` | short-lived JWT from RFC 7523 assertion | yes | none (federated) |
| `STATIC_BEARER` (legacy, opt-in) | static bearer | no | bearer secret |

### Consumer read contract (single-read lookup)

Resolve a provisioned external id to authority inputs in one `GetItem`:

```python
item = table.get_item(Key={'pk': f'USER#{external_id}', 'sk': f'USER#{external_id}'}).get('Item')
active = bool(item['active']) if item else False       # absent user = no authority
group_ids = sorted(item.get('groupIds', [])) if item else []
```

An absent user resolves to zero groups (fail-closed); an `active:false` user is
present but inactive. The consumer treats both as zero authority.

## Integration-verification runbook (carried, not CI)

The offline test suite proves RFC-7523/OAuth and SCIM conformance against a fake
IdP. The **only** thing that proves the whole chain against live Entra is an Entra
Test Connection. This is a deploy-time acceptance gate, run by an operator, not a
CI step. **This runbook does not trigger any deploy.**

1. Deploy the construct (in `OAUTH_CLIENT_CREDENTIALS` mode) to a dev account via
   the owning stack. Note `scim.tokenUrl`, `scim.scimUrl`, and
   `scim.clientSecretArn`.
2. **Operator sets the client secret out-of-band:** put the real client secret
   value into the Secrets Manager secret at `clientSecretArn` (console or an
   operator-run CLI). Never through automated tooling; the construct created it as
   a placeholder deliberately.
3. In Entra: create a non-gallery enterprise app, Provisioning -> Automatic,
   Authentication = **OAuth** (client-credentials). Enter the client id, the
   secret from step 2, the token URL (`scim.tokenUrl`), and the SCIM base URL
   (`scim.scimUrl`).
4. Click **Test Connection**. Green = the whole chain works against live Entra,
   including the token exchange tolerating Entra's dual-credential presentation
   (client credentials sent as both a Basic header and in the body). If it fails,
   read the Lambda's CloudWatch logs — the token endpoint logs each step of
   credential extraction and the specific rejection reason (this is why the token
   endpoint is self-hosted rather than a managed Cognito endpoint).
5. Record the result on the originating issue.

### Known constraint and future upgrades

- A custom (non-gallery) Entra app currently offers only **Bearer or OAuth** for
  provisioning auth; **Workload Identity Federation (WIF)** — the zero-stored-secret
  model — is gallery-only, and Microsoft's gallery SCIM onboarding is paused under
  the Secure Future Initiative. So OAuth client-credentials is the strongest
  posture available to a custom app today.
- **WIF** (`authMode: WIF`, RFC 7523) is designed in: the token endpoint already
  mints the same way; only the client-authentication half differs. Enable it when
  Entra exposes WIF for a custom app (or via a gallery listing), or for a
  non-Entra IdP that supports it now.
- **CAEP / Shared Signals Framework** (near-real-time revocation) is a future
  receiver endpoint, not built: the store already keys on the external id a future
  security-event token would carry. SCIM remains state-sync; revocation lag is
  mitigated by honouring `active` and short consumer token lifetimes.
