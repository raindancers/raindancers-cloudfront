# Scope Resolver — computed claims and principal tags at session mint

**Status:** SHIPPED (issue #47, branch `build/47-authz-constructs`)
**Scope:** `CognitoSessionBackend` / the custom-UI session mint
**Audience:** every consumer of the session construct (functional-self, horton,
ntrip, smart, agentl, raindancers-crew). This capability is **additive and
opt-in**; with it unconfigured, the construct behaves exactly as today.

## Usage (shipped shape)

```ts
new CognitoSessionBackend(this, 'Backend', {
  domainName, userPoolId, clientId, cognitoDomain,
  // opt-in: without this block the mint is byte-for-byte unchanged.
  scopeResolver: {
    endpointUrl: 'https://resolver.example.com/scope', // POST, JSON identity
    sharedSecretArn: 'arn:aws:secretsmanager:...:secret:resolver-bearer', // optional
    timeoutSeconds: 3, // default 3 (matches the identity hook)
  },
  scopeTokenMaxBytes: 7168, // default; mint is REFUSED over this, never truncated
  // jwtClaimsWhitelist gates which resolver keys are minted (reused as-is).
});
```

The resolver HTTP contract is a `POST <endpointUrl>` with
`{ "sub", "email", "provider": "cognito" }` (optionally `Authorization: Bearer
<sharedSecret>`), returning `{ "claims": {...}, "principal_tags": {...} }`.
Only `jwtClaimsWhitelist` keys are minted; a non-2xx / timeout / malformed body
fails the mint closed (no cookie). See `design.md` in the spec for the full
contract.

**Revocation window:** the minted token's TTL is the existing
`session_ttl_seconds` (default 3600 s) — there is no separate resolver TTL. That
TTL is the **maximum window before a changed authorization decision takes effect
in a live session**: a role or assignment changed in Permissions Admin is seen
only when the user's next session is minted or on the next refresh within the
TTL.

## Context

The custom-UI Cognito session layer mints a first-party, HMAC-signed session
token (`__Host-auth_session` / `__Secure-auth_session`) from a validated Cognito
id_token. Today it carries identity plus `roles` (from `cognito:groups`), and a
Pre-Token-Generation trigger (`lambda/pre-token`) already injects both `roles`
and the AWS principal-tags claim
(`https://aws.amazon.com/tags/principal_tags/Claims`) from group membership. The
session mint Lambda (`lambda/cognito-customui-session`) already has
`call_identity_hook`: a POST to a configured URL with the authenticated
identity, whose response is merged into the mint.

A consumer (horton) needs the session token to carry **computed, per-user
authorization scope** — not pass-through group names, but a scope object derived
from the consumer's own authority store (role bitmasks per brand, plus the brand
values that must become session tags). The consumer then exchanges the session
for scoped AWS credentials (`AssumeRole` + session tags), so the computed claims
and principal tags are the bridge from the consumer's authority model to AWS
enforcement.

## Decision

**Add an optional Scope Resolver to the session mint: a consumer-supplied
resolver, invoked at mint with the authenticated identity, whose returned claims
and principal tags are merged into the session token subject to
`jwtClaimsWhitelist`. The resolver is a generalisation of the existing
`call_identity_hook` + pre-token principal-tags pattern. When no resolver is
configured, the mint is byte-for-byte unchanged.**

### Shape

- **Prop:** `scopeResolver?` on `CognitoSessionBackendProps` — a resolver
  endpoint (URL) or Lambda reference. Absent by default.
- **Invocation:** at mint, after id_token validation, the Lambda calls the
  resolver with the verified identity (`sub`/`oid`, `email`). Same call shape and
  failure handling as `call_identity_hook` (timeout, non-2xx => fail closed:
  no session issued).
- **Merge:** the resolver returns (a) a set of custom claims (e.g. the consumer's
  scope object) and (b) a set of principal tags. Both are merged into the
  session token, each key checked against `jwtClaimsWhitelist` — a key not on
  the whitelist is dropped, not minted. The principal-tags claim follows the
  existing pre-token format.
- **Size guard:** the mint measures the assembled token and refuses to issue if
  it exceeds a configured ceiling (default within the ~8 KB cookie budget).
  Overflow is an explicit mint failure (logged), never truncation — a truncated
  scope is a security defect. (The consumer is expected to encode compactly;
  horton uses role bitmasks, see horton ADR.)

### What stays the consumer's responsibility

- Computing scope (the resolver is the consumer's code; the construct only calls
  it and merges the result).
- The meaning of the claims and tags (the construct is agnostic — it signs and
  carries whatever the whitelist permits).

## Consequences

- **Backward compatible.** No `scopeResolver` => no behaviour change. Existing
  consumers are untouched; this is why it is opt-in, not a new default.
- **One trust boundary added, small and testable.** The resolver is the only new
  code on the mint path; everything else (HMAC signing, KVS secret, revocation
  denylist, audit) is unchanged. The whitelist remains the gate on what a
  resolver can inject.
- **Fail-closed.** A resolver error means no session is minted, matching the
  identity-hook posture.
- **The principal-tags path already exists** (pre-token), so emitting session
  tags for `AssumeRole` is a reuse, not a new mechanism.

## Implementation seam (grounded in the source)

- `lambda/cognito-customui-session/index.py` — where `session_payload` is built
  and `cognito:groups -> roles` is copied: add the resolver call and merge here.
  `call_identity_hook` is the template for the call.
- `lambda/pre-token/index.py` — the existing claims + principal-tags injector;
  the resolver generalises its group pass-through into a computed result.
- `cognitoSessionBackend.ts` — add `scopeResolver?` to props and wire it +
  the whitelist through to the mint Lambda's config.

## Open

- Resolver transport: HTTP endpoint vs direct Lambda invoke (both fit the
  existing config pattern; HTTP mirrors `call_identity_hook` exactly).
- The exact `jwtClaimsWhitelist` entries a consumer must add for its scope claim
  and the principal-tags claim.

## Entra mint parity (0.0.53)

The resolver merge above is implemented on the **Cognito** mint
(`lambda/cognito-customui-session/index.py`, `CognitoSessionBackend`). The
**Entra** mint (`lambda/edge-auth/oauth-callback.py`, `AuthInfrastructure`) is a
separate construct for consumers whose IdP is Microsoft Entra (not Cognito), and
it already had an older `post_auth_hook_url` that validates the identity and
merges a hook's `additional_claims` into `session_payload`. `0.0.53` brings that
Entra mint to parity with the Cognito resolver for the two things the hook did
not cover:

- **Token-size overflow-refuse.** Before signing, the assembled token
  (`header.payload.signature`) is measured with the SAME arithmetic as the
  Cognito guard — `len(header_b64) + 1 + len(payload_b64) + 1 + 43` — and refused
  over `scope_token_max_bytes` (default 7168). Never truncated. Surfaced as the
  `scopeTokenMaxBytes` prop on `AuthInfrastructure`; omitted from the config
  secret when unset, so existing Entra consumers are byte-for-byte unchanged.
- **First-class principal tags.** A hook result's `principal_tags` map is encoded
  into the `https://aws.amazon.com/tags/principal_tags/Claims` claim in the same
  `:k=v:` shape the pre-token injector and the Cognito resolver emit, gated by
  the whitelist exactly like a role claim — so the `AssumeRole` path reads one
  format regardless of IdP.

Role-mask claims (`g`/`b`) already rode through the Entra hook's
`additional_claims` merge. The two mints are kept as independent
implementations (no shared helper) because they bundle into separate edge
Lambdas; the encoding and guard are mirrored, not shared.
