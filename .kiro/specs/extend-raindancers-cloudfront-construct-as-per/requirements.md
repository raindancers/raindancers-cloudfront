# Requirements — Extend raindancers-cloudfront: Scope Resolver + Permissions Admin

Tracks [issue #47](https://github.com/raindancers/raindancers-cloudfront/issues/47).
Design docs: `src/cloudfront/patterns/SCOPE_RESOLVER.md`, `src/cloudfront/patterns/PERMISSIONS_ADMIN.md`.
First consumer: [horton](https://github.com/bwip-holdings/horton/issues/181).

## Introduction

This feature adds two reusable, opt-in authorization constructs to the
`raindancers-cloudfront` CDK package, so consumers no longer build a bespoke
authorization surface each time.

- **Scope Resolver (read side)** — extends the existing `CognitoSessionBackend`
  custom-UI session mint so a consumer-supplied resolver can resolve a user's
  **assignments** into the two parts of their authorization and inject both into
  the minted HMAC session token:
  - **role** → a computed **claim** (role bitmasks per scope), consumed by the
    consumer app's own authorization checks;
  - **scope** → a **principal tag**, consumed by `AssumeRole` session tags for
    AWS-level enforcement.
  Despite the name, the resolver reads the whole `(role, scope)` model, not
  scope alone.
- **Permissions Admin (write side)** — a new construct: an admin SPA plus a
  management-API shell for roles, scopes, and assignments, with the authority
  invariants enforced server-side. Domain-neutral; the consumer injects
  catalogue, store, and scope dimension.

### Model: role, scope, assignment

Role and scope are co-equal, orthogonal parts of one authority model; an
assignment binds them to a principal.

- **Role** — *what* permissions you get: a named subset of the permission
  catalogue, represented as 16-bit masks (Requirement 13). Role → session
  **claim**.
- **Scope** — *where* a role applies: the consumer's scope dimension. For horton,
  scope = **brand**. Scope → principal **tag**.
- **Assignment** — binds the two to a principal: *principal → role → scope*
  ("Alice has the Editor role on Brand X"). The resolver turns a user's
  assignments into role claims + scope tags; Permissions Admin is where
  assignments, roles, and scopes are created and granted.

The word "scope" throughout these documents is the generic term; "brand" is only
horton's injected meaning and SHALL NOT appear in the construct.

Both constructs are **additive and opt-in**. With neither configured, the
package behaves byte-for-byte as it does today, and the existing consumers
(functional-self, ntrip, smart, agentl, raindancers-crew) are unaffected.

### Decided parameters (fixed inputs, from the issue — not up for re-decision)

- Role cap is **16 per mask** (two masks: predefined, custom).
- Session token TTL default **3600 s (1 h), configurable** via the existing
  `session_ttl_seconds`; this is the revocation window control.
- Downstream cutover is **straight (no shadow run)**, so **automated test
  coverage is the safety gate** — every behaviour below lands with a test.

### Out of scope (lives in other repos)

- horton's concrete resolver implementation, DynamoDB table re-key, and the
  assumed-role plumbing — [horton #181](https://github.com/bwip-holdings/horton/issues/181).
- Any consumer-specific permission catalogue, predefined role set, or scope
  source. The constructs only consume these as injected configuration.

---

## Requirements

### Requirement 1 — Scope Resolver is opt-in and backward compatible

**User story:** As a maintainer of an existing consumer (functional-self, ntrip,
smart, agentl, raindancers-crew), I want the Scope Resolver to change nothing
unless I opt in, so that upgrading the package does not alter my minted sessions.

**Acceptance criteria:**

1. WHEN a consumer instantiates `CognitoSessionBackend` WITHOUT a
   `scopeResolver` prop THEN the synthesized template and the mint Lambda's
   runtime behaviour SHALL be byte-for-byte identical to the current release.
2. WHEN `scopeResolver` is absent THEN the mint Lambda SHALL NOT make any
   resolver call and SHALL NOT add any resolver-derived claim or principal tag
   to the session token.
3. A snapshot/assertion test SHALL prove criterion 1 — that a backend without a
   resolver emits the unchanged mint configuration.

### Requirement 2 — Resolver resolves assignments into role claims and scope tags

**User story:** As a consumer with my own authority store, I want a resolver I
supply to be called at session mint and its computed **role** claims plus
**scope** principal tags merged into the session token, so that the token
carries both *what* the user may do and *where*, rather than only pass-through
group names.

**Acceptance criteria:**

1. WHEN `scopeResolver` is configured AND a session is minted AFTER successful
   id_token validation THEN the mint Lambda SHALL call the resolver over HTTP
   (POST to a configured endpoint URL) with the verified identity (at least
   `sub`/`oid` and `email`), reusing the existing `call_identity_hook` call
   shape (optional bearer secret, bounded timeout).
2. WHEN the resolver returns (a) a set of custom **claims** (the role bitmasks
   per scope) AND (b) a set of **principal tags** (the scope values, e.g.
   brands) THEN the mint Lambda SHALL merge the claims into the session token as
   signed claims AND SHALL format the principal-tags claim
   (`https://aws.amazon.com/tags/principal_tags/Claims`) in the same shape the
   existing pre-token injector uses.
3. The resolver call SHALL occur at the point in `cognito-customui-session`
   where `session_payload` is built and `cognito:groups -> roles` is copied.
4. A test SHALL assert that resolver-returned whitelisted role claims appear as
   token claims AND resolver-returned whitelisted scope values appear in the
   principal-tags claim, each in the correct format.

### Requirement 3 — Only whitelisted keys are minted

**User story:** As a security reviewer, I want the `jwtClaimsWhitelist` to be the
sole gate on what a resolver can inject, so that a misbehaving or compromised
resolver cannot add arbitrary claims to a signed session.

**Acceptance criteria:**

1. WHEN the resolver returns a claim or principal-tag key THAT IS on
   `jwtClaimsWhitelist` THEN the mint Lambda SHALL include it in the signed
   token.
2. WHEN the resolver returns a claim or principal-tag key THAT IS NOT on
   `jwtClaimsWhitelist` THEN the mint Lambda SHALL drop that key (not mint it)
   and SHALL NOT fail the mint on account of the dropped key.
3. A test SHALL assert that a non-whitelisted key returned by the resolver is
   absent from the minted token while a whitelisted key from the same response
   is present.

### Requirement 4 — Resolver failure fails closed

**User story:** As a security reviewer, I want a resolver error or timeout to
prevent a session from being issued, so that a user can never receive a session
with missing or stale scope.

**Acceptance criteria:**

1. WHEN the resolver call times out THEN the mint Lambda SHALL NOT issue a
   session and SHALL return an explicit error response (no `Set-Cookie`).
2. WHEN the resolver returns a non-2xx status OR a malformed body THEN the mint
   Lambda SHALL NOT issue a session and SHALL return an explicit error response.
3. The failure posture SHALL match the existing identity-hook posture (the hook
   failure path that returns `identity_unavailable` without a cookie).
4. A test SHALL assert that a resolver timeout and a resolver non-2xx each
   result in no session cookie being set.

### Requirement 5 — Token size is bounded and never silently truncated

**User story:** As a consumer, I want the mint to refuse rather than truncate a
token that exceeds the cookie budget, so that a partial set of role claims or
scope tags is never signed and issued.

**Acceptance criteria:**

1. The construct SHALL expose a `scopeTokenMaxBytes` prop with a default within
   the ~8 KB browser cookie budget.
2. WHEN the assembled session token's serialized size exceeds
   `scopeTokenMaxBytes` THEN the mint Lambda SHALL refuse to issue the session,
   SHALL log the overflow, AND SHALL return an explicit error response — it
   SHALL NOT truncate the token or drop role claims or scope tags to fit.
3. A test SHALL assert that an over-budget assembled token yields a mint refusal
   (explicit error, no cookie) rather than a truncated token.

### Requirement 6 — Session TTL is the documented revocation window

**User story:** As an operator, I want the session TTL surfaced and documented as
the revocation-window control, so that I understand the maximum lifetime of a
scope decision baked into a token.

**Acceptance criteria:**

1. The minted scope token's TTL SHALL be the existing `session_ttl_seconds`
   (default 3600 s), with no separate resolver TTL introduced.
2. The construct documentation SHALL state that `session_ttl_seconds` is the
   maximum window before a changed authorization decision takes effect in a
   live session.

### Requirement 7 — Permissions Admin is a reusable, domain-neutral construct

**User story:** As a consumer owning a role/permission/assignment model, I want a
reusable `PermissionsAdmin` construct that manages roles, scopes, and
assignments, so that I do not re-build a security-sensitive admin surface per
project.

**Acceptance criteria:**

1. The package SHALL export a new `PermissionsAdmin` construct alongside
   `CognitoSessionBackend`.
2. The construct SHALL name no consumer domain term (no `brand`, `subject`, or
   other horton concept) in its public API, resources, or code; domain meaning
   SHALL enter only through injected configuration.
3. A test SHALL assert that the construct's public prop surface and synthesized
   resource names contain no hardcoded consumer domain term.

### Requirement 8 — Consumer injects catalogue, store, and scope dimension

**User story:** As a consumer, I want to inject my own permission catalogue,
predefined roles, store tables, scope dimension, and management-permission
gating, so that the construct carries my authority model without me forking it.

**Acceptance criteria:**

1. The construct SHALL accept an injected **permission catalogue** (atomic
   permissions and their names).
2. The construct SHALL accept injected **predefined roles** (names plus their
   permission subsets) and a **rights-act lockout set** (consumer-named
   permissions that can never be added through this surface).
3. The construct SHALL accept injected **store** references — the DynamoDB
   tables for roles and assignments — and SHALL read/write only through those
   references (store-agnostic within DynamoDB), mirroring how
   `CognitoSessionBackend` takes pool identifiers.
4. The construct SHALL accept an injected **scope dimension** (what a scope is
   and its source) plus the estate-vs-scope split.
5. The construct SHALL accept injected **management permissions** that gate each
   admin operation.

### Requirement 9 — The admin SPA reflects the caller's own permissions, fail-closed

**User story:** As an administrator, I want the admin SPA to show only the
management actions my permissions allow, hidden by default, so that the UI never
implies I can perform an action the API will reject.

**Acceptance criteria:**

1. The admin SPA SHALL present Roles, Scopes, and Assignments screens, served
   through the consumer's existing CloudFront distribution.
2. WHEN the caller lacks a given management permission THEN the corresponding
   action in the SPA SHALL be hidden (fail-closed to hidden, not merely
   disabled).
3. The SPA SHALL be the convenience layer only; it SHALL NOT be the place any
   authority invariant is enforced (see Requirement 11).

### Requirement 10 — Management API gates every operation by its required permission

**User story:** As a security reviewer, I want every management operation to
carry and check its required management permission server-side, so that calling
the API directly cannot bypass the SPA's gating.

**Acceptance criteria:**

1. The management-API shell SHALL expose create/delete/list for roles and
   assignments, each operation declaring the management permission it requires.
2. WHEN a caller invokes an operation WITHOUT the required management permission
   THEN the API SHALL deny the operation (fail-closed) regardless of the SPA.
3. Every denial and every mutation SHALL be observable for audit (see
   Requirement 12).
4. A test SHALL assert that an operation invoked without its required permission
   is denied.

### Requirement 11 — Authority invariants are enforced server-side and cannot be bypassed

**User story:** As a security reviewer, I want no-escalation, rights-act lockout,
predefined-role immutability, and archive-not-delete enforced in the construct's
server code, so that no consumer and no direct API call can bypass them.

**Acceptance criteria:**

1. **No-escalation** — WHEN an administrator attempts to put into a role any
   permission they do not themselves hold THEN the operation SHALL be denied.
2. **Rights-act lockout** — WHEN any operation attempts to add a permission in
   the consumer-named lockout set to a role through this surface THEN the
   operation SHALL be denied, for every caller without exception.
3. **Immutable predefined roles** — WHEN an operation attempts to edit, rename,
   delete, or create a custom role that shadows a predefined role THEN it SHALL
   be denied.
4. **Archive-not-delete** — WHEN a role that is referenced by one or more
   assignments is deleted THEN the construct SHALL archive it (retain, mark
   archived) rather than hard-delete it.
5. Tests SHALL assert that each dangerous case in criteria 1–4 is denied — the
   tests prove the invariants cannot be bypassed, since cutover relies on test
   coverage as the safety gate.

### Requirement 12 — Every mutation is audited with the acting principal

**User story:** As an auditor, I want every role/assignment create, edit, and
archive stamped with the acting principal, so that every authority change is
attributable.

**Acceptance criteria:**

1. WHEN any role or assignment is created, edited, or archived THEN the
   construct SHALL record an audit entry stamped with the acting principal and
   the operation.
2. A denied operation SHALL also be observable (logged) so that attempted
   escalations are visible.
3. A test SHALL assert that a successful mutation produces an audit record
   carrying the acting principal.

### Requirement 13 — Two-mask role model with a permanent bit registry

**User story:** As a consumer, I want roles represented as predefined and custom
16-bit masks per scope, with role-bit assignments that are permanent, so that a
scope claim stays stable and a retired role's bit is never silently reused.

**Acceptance criteria:**

1. The construct SHALL represent roles as two 16-bit masks per scope — a
   predefined mask and a custom mask.
2. The construct SHALL own a bit-assignment registry such that a custom role is
   assigned a fixed bit within its scope.
3. WHEN a custom role is deleted/archived THEN its bit SHALL be retired and
   SHALL NOT be reassigned to a different role.
4. A test SHALL assert that a retired bit is not reused by a subsequently
   created custom role.

### Requirement 14 — SPA is bundled and served through the existing front door

**User story:** As a consumer, I want the admin SPA delivered the same way the
package already deploys front-ends, so that I serve it from the CloudFront
distribution I already run without a separate build step.

**Acceptance criteria:**

1. The construct SHALL deliver the admin SPA as bundled static assets, deployed
   through the package's existing front-end deployment mechanism
   (`ViteFrontendDeployment` pattern) to the consumer's distribution.
2. The SPA SHALL be reachable under a configurable path prefix on the
   consumer's existing distribution, not on a separate domain.
3. A test SHALL assert that instantiating the construct wires a bundled-asset
   deployment targeted at the injected distribution/bucket.
