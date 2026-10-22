# Design — Extend raindancers-cloudfront: Scope Resolver + Permissions Admin

Implements the requirements in `requirements.md` for
[issue #47](https://github.com/raindancers/raindancers-cloudfront/issues/47).
Grounded in `src/cloudfront/patterns/SCOPE_RESOLVER.md`,
`src/cloudfront/patterns/PERMISSIONS_ADMIN.md`, and the existing source seams.

## Settled decisions (from `.spec-state.json`)

- **Role vs scope in the token:** role → signed **claim** (16-bit bitmasks per
  scope); scope → **principal tag** (for `AssumeRole` session tags).
- **Resolver transport:** HTTP endpoint (POST to a configured URL), mirroring
  the existing `call_identity_hook` exactly.
- **Management API placement:** a **regional API** (API Gateway HTTP API +
  regional Lambda) behind the consumer's existing CloudFront distribution, not
  Lambda@Edge. Rationale: the admin surface does DynamoDB reads/writes and is
  not latency-critical; Lambda@Edge's code-size limit, region pinning to
  us-east-1, and lack of environment variables make it a poor fit for a CRUD
  management API.

---

## Overview

Three cooperating pieces of one authority model, all served from the front door
a consumer already runs:

```
                    ┌───────────────────── Permissions Admin (NEW, write side) ─────────────────────┐
  Administrator ──▶ │ admin SPA (bundled)  ──▶  Management API (regional, behind CloudFront)        │
                    │                             │  enforces: no-escalation, rights-act lockout,   │
                    │                             │  immutable predefined roles, archive-not-delete,│
                    │                             │  audit; owns the custom-role bit registry       │
                    └──────────────────────────────────────────┬──────────────────────────────────┘
                                                                ▼ writes
                                              ┌──────── role + assignment store (injected DynamoDB) ───────┐
                                                                ▲ reads
  User logs in  ──▶ CognitoSessionBackend mint ──▶ Scope Resolver (NEW, read side, HTTP) ──────────────────┘
                    (cognito-customui-session)      resolves assignments → role claims + scope tags
                                   │ signs
                                   ▼
                    HMAC session token: roles=<bitmasks per scope> (claim)
                                        principal_tags=<scope values> (tag)
                                   │
  Consumer app  ──▶ AssumeRole with session tags ──▶ scoped AWS credentials
```

- **Scope Resolver** is a minimal, additive extension of the *existing*
  `CognitoSessionBackend` mint path. No new construct; a few new props and a
  bounded block of Lambda code.
- **Permissions Admin** is a *new* construct (`PermissionsAdmin`) exported from
  the patterns barrel. It owns the SPA, the regional management API, the
  server-side invariants, and the custom-role bit registry.
- Everything stays **opt-in**: a consumer that configures neither sees today's
  behaviour byte-for-byte.

---

## Component 1 — Scope Resolver (extends `CognitoSessionBackend`)

### CDK surface (`cognitoSessionBackend.ts`)

Two new optional props on `CognitoSessionBackendProps`:

```ts
export interface CognitoSessionBackendProps {
  // ... existing props unchanged ...

  /**
   * Opt-in scope resolver. When set, the session mint POSTs the verified
   * identity to this HTTPS endpoint and merges the returned role claims and
   * scope principal tags into the minted token (subject to jwtClaimsWhitelist).
   * Absent by default — mint is byte-for-byte unchanged without it.
   */
  readonly scopeResolver?: ScopeResolverConfig;

  /**
   * Ceiling (bytes) on the assembled session token. Over this, the mint is
   * REFUSED (explicit error, logged) — never truncated. @default 7168 (within
   * the ~8 KB browser cookie budget, leaving headroom for cookie attributes).
   */
  readonly scopeTokenMaxBytes?: number;
}

export interface ScopeResolverConfig {
  /** HTTPS endpoint the mint POSTs the verified identity to. */
  readonly endpointUrl: string;
  /**
   * Secrets Manager ARN of a shared bearer secret sent as
   * `Authorization: Bearer <secret>`. Optional; mirrors the identity hook.
   */
  readonly sharedSecretArn?: string;
  /** Request timeout seconds. @default 3 (matches call_identity_hook). */
  readonly timeoutSeconds?: number;
}
```

Wiring (mirrors how `jwtClaimsWhitelist` and the identity hook already flow):

- `CognitoAuthSecretManager` writes `scope_resolver_url`,
  `scope_resolver_secret_arn`, `scope_resolver_timeout`, and
  `scope_token_max_bytes` into the **config secret** the mint Lambda already
  reads via `get_config()`.
- If `scopeResolver.sharedSecretArn` is set, grant the mint Lambda's role
  `secretsmanager:GetSecretValue` on it (same grant shape as the identity-hook
  secret).
- `jwtClaimsWhitelist` is already a prop and already lands in the config secret;
  no new whitelist plumbing — the resolver reuses it as the merge gate.

Default `scopeTokenMaxBytes = 7168`. The `__Host-`/`__Secure-` cookie carries
the whole token; the 7168-byte default leaves ~1 KB for the cookie name and
attributes under the common 8 KB per-cookie limit.

### Lambda change (`lambda/cognito-customui-session/index.py`)

Add a resolver call modelled on the existing `call_identity_hook`. The insertion
point is step 3, where `session_payload` is built and `cognito:groups -> roles`
is copied.

New helper (sibling of `call_identity_hook`, same failure semantics):

```python
def call_scope_resolver(url, secret, identity, timeout):
    """POST the verified identity to the consumer's resolver.
    Returns (status, {'claims': {...}, 'principal_tags': {...}}).
    Same shape/failure handling as call_identity_hook."""
```

Merge logic, inserted after the `roles` copy and before signing:

```python
resolver_url = config.get('scope_resolver_url', '')
if resolver_url:
    status, result = call_scope_resolver(
        resolver_url, get_scope_resolver_secret(),
        {'sub': sub, 'email': email, 'provider': 'cognito'},
        int(config.get('scope_resolver_timeout', '3')),
    )
    # Fail closed: any non-2xx / malformed body / timeout => no session.
    if status < 200 or status >= 300 or not isinstance(result, dict):
        logger.error(f'Scope resolver failed: status={status}')
        return _json_response(503, {'error': 'scope_unavailable'})

    whitelist = set(json.loads(config.get('jwt_claims_whitelist', '[]')))

    # (a) role claims — merged only if whitelisted.
    for k, v in (result.get('claims') or {}).items():
        if k in whitelist:
            session_payload[k] = v

    # (b) scope principal tags — merged into the pre-token tag format,
    #     gated by the same whitelist entry for the principal-tags claim.
    tags = result.get('principal_tags') or {}
    tag_claim = 'https://aws.amazon.com/tags/principal_tags/Claims'
    if tags and tag_claim in whitelist:
        # same ':a:b:' shape the pre-token injector emits
        session_payload[tag_claim] = ':' + ':'.join(
            f'{name}={value}' for name, value in tags.items()
        ) + ':'

# Size guard — refuse, never truncate.
max_bytes = int(config.get('scope_token_max_bytes', '7168'))
payload_b64 = base64url_encode(json.dumps(session_payload, separators=(',', ':')).encode())
assembled = f'{header_b64}.{payload_b64}'
if len(assembled) + 1 + 43 > max_bytes:  # +sig segment (HS256 b64url ≈ 43)
    logger.error(f'Assembled session token exceeds {max_bytes} bytes; refusing mint')
    return _json_response(500, {'error': 'scope_token_too_large'})
```

Key properties mapped to requirements:

- **R1** — guarded by `if resolver_url:`; absent ⇒ no call, no new claims, mint
  unchanged.
- **R2** — HTTP POST with identity; role claims merged as claims, scope values
  merged into the principal-tags claim in the pre-token `:k=v:` shape.
- **R3** — whitelist is the only gate; non-whitelisted keys never reach
  `session_payload`, and a dropped key does not fail the mint.
- **R4** — any resolver failure returns `503 scope_unavailable` before any
  `Set-Cookie`, matching the `identity_unavailable` posture.
- **R5** — the size check runs on the *assembled* token; over budget ⇒
  `500 scope_token_too_large`, logged, no cookie. The guard is computed before
  the final `cookie_value` is built, so truncation is impossible.
- **R6** — TTL is the existing `session_ttl_seconds`; no new TTL. Documented in
  the construct README as the revocation window.

### Resolver response contract (documented, consumer-implemented)

```
POST <endpointUrl>
  Authorization: Bearer <sharedSecret?>
  { "sub": "...", "email": "...", "provider": "cognito" }

200 OK
  {
    "claims":        { "roles": { "<scopeId>": { "predefined": <0-65535>, "custom": <0-65535> } } },
    "principal_tags": { "<tagName>": "<scopeValue>" }
  }
non-2xx / timeout / malformed ⇒ mint fails closed (no session)
```

The construct is agnostic to the claim/tag *contents*; it signs and carries what
the whitelist permits. horton's resolver lives in horton
([#181](https://github.com/bwip-holdings/horton/issues/181)).

---

## Component 2 — `PermissionsAdmin` construct (new, write side)

A new construct file `src/cloudfront/patterns/permissionsAdmin.ts`, exported from
`src/cloudfront/patterns/index.ts`.

### CDK surface

```ts
export interface PermissionsAdminProps {
  /** Canonical domain, for default resource names (as CognitoSessionBackend). */
  readonly domainName: string;

  /** The consumer's existing CloudFront distribution and asset bucket. */
  readonly distribution: cloudfront.IDistribution;
  readonly assetBucket: s3.IBucket;
  /** Path prefix the admin SPA + API mount under. @default 'admin' */
  readonly pathPrefix?: string;

  /** Injected authority model — all domain meaning enters here (R7, R8). */
  readonly catalogue: PermissionCatalogue;
  readonly predefinedRoles: PredefinedRole[];
  readonly rightsActLockout: string[];        // permission ids never grantable here
  readonly scopeDimension: ScopeDimension;     // what a "scope" is + its source
  readonly managementPermissions: ManagementPermissionMap;

  /** Injected store — construct reads/writes only through these refs (R8.3). */
  readonly roleTable: dynamodb.ITable;
  readonly assignmentTable: dynamodb.ITable;
  readonly bitRegistryTable: dynamodb.ITable;  // custom-role bit registry (R13)

  /** How the API authenticates the caller (the minted session + reflection). */
  readonly callerIdentity: CallerIdentityConfig;
  /** Audit sink — reuses the package's AuditLogArchive wiring. */
  readonly auditLogRetentionDays?: number;
}

export interface PermissionCatalogue {
  /** Atomic permissions: stable id → human name. No domain term in the API. */
  readonly permissions: { readonly id: string; readonly name: string }[];
}

export interface PredefinedRole {
  readonly id: string;
  readonly name: string;
  readonly permissionIds: string[];   // subset of the catalogue
}

export interface ScopeDimension {
  /** Generic label, e.g. 'scope' — NOT 'brand'. */
  readonly label: string;
  /** Where the live scope list comes from (SSM param / table / static). */
  readonly source: ScopeSource;
  /** Which operations are estate-level (no scope) vs scope-level. */
  readonly estateLevelPermissionIds: string[];
}

export interface ManagementPermissionMap {
  readonly createRole: string;
  readonly deleteRole: string;
  readonly listRoles: string;
  readonly createAssignment: string;
  readonly deleteAssignment: string;
  readonly listAssignments: string;
}
```

No prop, resource name, or type contains `brand`/`subject`/any horton term
(**R7.2**); the only domain input is `ScopeDimension.label` and the injected
catalogue/roles, which the consumer supplies.

### Architecture

```
CloudFront distribution (consumer's)
  ├── /<prefix>/*            → S3 asset bucket (bundled admin SPA)   [R9, R14]
  └── /<prefix>/api/*        → API Gateway HTTP API (regional)       [R10]
                                 └── management Lambda (regional, Python)
                                       ├── authN: validates the HMAC session cookie
                                       ├── authZ: checks managementPermissions per op
                                       ├── invariants: no-escalation, rights-act,
                                       │   immutable predefined, archive-not-delete
                                       ├── bit registry: allocate/retire custom bits
                                       └── audit: AuditLogArchive (actor-stamped)
                                 reads/writes → roleTable, assignmentTable, bitRegistryTable
```

A new CloudFront behaviour for `/<prefix>/api/*` points at an API Gateway HTTP
API origin; `/<prefix>/*` serves the SPA from the asset bucket (same OAC the
package already uses). The SPA is deployed with the existing
`ViteFrontendDeployment` pattern (bundled static assets, `destinationKeyPrefix`
= the path prefix), satisfying **R14**.

### Management Lambda — operations and invariants

Regional Python Lambda (standard Lambda, env vars + full DynamoDB SDK). One
handler, routed by method + path. Every op runs the same gate order:

1. **AuthN** — parse and HMAC-verify the `__Host-auth_session` cookie (reuse the
   package's existing session verification helper). No valid session ⇒ 401.
2. **AuthZ** — look up the op's required permission from `managementPermissions`;
   confirm the caller's own role claims include it. Missing ⇒ 403 (**R10.2**).
   This mirrors the permission-less reflection route pattern already in the
   package (caller's own set, fail-closed).
3. **Invariant checks** (server-side, **R11**):
   - *No-escalation* — for `createRole`/edit, every permission id being placed
     into the role MUST be a subset of the caller's own held permissions; else
     403 (**R11.1**).
   - *Rights-act lockout* — if any permission id ∈ `rightsActLockout` appears in
     the role body, deny unconditionally, for every caller (**R11.2**).
   - *Immutable predefined* — reject edit/rename/delete of any `predefinedRoles`
     id, and reject a custom role whose id/name shadows a predefined one
     (**R11.3**).
   - *Archive-not-delete* — on `deleteRole`, if the role is referenced by ≥1
     assignment, set `status=archived` + retire its bit (below) instead of
     removing the item (**R11.4, R13.3**).
4. **Mutation** — write through the injected table ref only.
5. **Audit** — write an actor-stamped entry (acting principal `sub`, op,
   target, timestamp) via `AuditLogArchive`; denials are logged too (**R12**).

### Two-mask role model + bit registry (**R13**)

- A role is identified within a scope by one bit in one of two 16-bit masks:
  **predefined** (fixed by `predefinedRoles`) or **custom** (allocated).
- `bitRegistryTable` records each custom role's permanent bit:
  `pk = SCOPE#<scopeId>`, `sk = BIT#<n>`, `roleId`, `status` (`active`/`retired`).
- Allocation picks the lowest free bit 0–15 in the custom mask for that scope;
  if all 16 are taken (active or retired), allocation **fails** (cap is 16, from
  the issue). A retired bit is never handed to a new role (**R13.3**), so a scope
  claim minted from an old assignment can never silently mean a different role.
- Deleting/archiving a custom role sets its registry row `status=retired`; the
  bit stays reserved.

### Store contract (injected, DynamoDB) — **R8.3**

The construct assumes only these access patterns, so a consumer can back them
with any DynamoDB table shape that supports them:

- **roleTable**: item per role — `pk=ROLE#<id>`, attrs `name`, `scopeId|ESTATE`,
  `mask` (predefined|custom), `bit`, `permissionIds` (set), `status`. GSI on
  `scopeId` to list roles in a scope.
- **assignmentTable**: item per `(principal, role, scope)` —
  `pk=PRINCIPAL#<id>`, `sk=ROLE#<roleId>#SCOPE#<scopeId>`. GSI on `roleId` to
  answer "is this role in use?" for archive-not-delete.
- **bitRegistryTable**: as above.

The construct never assumes attribute meaning beyond these keys; the resolver
(read side) uses the same tables to compute claims/tags.

### Admin SPA (**R9, R14**)

- Bundled React/Vite static app shipped inside the construct's asset directory,
  deployed via `ViteFrontendDeployment` to `/<prefix>/` on the consumer's
  distribution.
- On load it calls a reflection endpoint (the caller's own management
  permissions) and renders only the actions the caller holds — **fail-closed to
  hidden**, not disabled (**R9.2**). The SPA enforces nothing; it is a
  convenience over the API, which is the sole enforcement point (**R9.3**).
- Screens: Roles (list/create/archive), Scopes (list, read-only from the
  injected source), Assignments (grant/revoke).

---

## Data flow — one assignment, end to end

```
Admin grants "Editor on Scope X" to Alice
  → SPA POST /admin/api/assignments  (carries Alice, Editor roleId, Scope X)
  → management Lambda: authN(admin session) → authZ(createAssignment perm)
      → no-escalation: admin holds Editor's perms? → rights-act clear?
      → write assignmentTable  → audit(actor=admin)
Alice logs in later
  → CognitoSessionBackend mint → scope resolver POSTs {sub: Alice}
      → resolver reads assignmentTable+roleTable → { claims: {roles:{X:{custom:0b...}}},
                                                     principal_tags:{scope:"X"} }
      → whitelist gate → size guard → HMAC-signed session cookie
Alice's app
  → AssumeRole with session tag scope=X → scoped AWS creds
```

---

## Testing strategy (the safety gate — straight cutover, no shadow run)

Jest (CDK assertions) + Python unit tests, matching the existing
`test/*.test.ts` and `lambda/**/tests/test_*.py` layout.

**Scope Resolver (Python, `cognito-customui-session/tests`):**

- `test_mint_unchanged_without_resolver` — no `scope_resolver_url` ⇒ identical
  `session_payload` (R1).
- `test_resolver_claims_and_tags_merged` — whitelisted role claim appears as a
  claim; whitelisted scope appears in the `:k=v:` principal-tags claim (R2).
- `test_non_whitelisted_dropped` — non-whitelisted key absent, whitelisted key
  present, mint still succeeds (R3).
- `test_resolver_timeout_fails_closed` and `test_resolver_non2xx_fails_closed`
  — no `Set-Cookie`, 503 (R4).
- `test_oversize_token_refused` — assembled token over `scope_token_max_bytes`
  ⇒ 500 `scope_token_too_large`, no cookie (R5).

**Scope Resolver (CDK, `test/cognito-session-backend.test.ts`):**

- snapshot: backend without `scopeResolver` emits unchanged config secret (R1.3).
- with resolver: config secret carries `scope_resolver_url` and the grant exists.

**PermissionsAdmin (CDK, `test/permissions-admin.test.ts`):**

- SPA deployment targets the injected bucket/distribution under the prefix
  (R14.3).
- `/<prefix>/api/*` behaviour routes to the regional API; `/<prefix>/*` to S3.
- no synthesized logical name / prop contains `brand` or `subject` (R7.3).

**PermissionsAdmin invariants (Python, `permissions-admin/tests`):**

- `test_no_escalation_denied` — granting a permission the caller lacks ⇒ 403
  (R11.1).
- `test_rights_act_lockout_denied` — any lockout permission ⇒ denied for every
  caller (R11.2).
- `test_predefined_role_immutable` — edit/rename/delete/shadow ⇒ denied (R11.3).
- `test_inuse_role_archived_not_deleted` — delete of a role with an assignment
  ⇒ archived, item retained (R11.4).
- `test_missing_management_permission_denied` — op without its perm ⇒ 403
  (R10.4).
- `test_mutation_audited_with_principal` — successful grant writes an audit row
  stamped with the actor (R12.3).
- `test_retired_bit_not_reused` — delete a custom role, create another in the
  same scope ⇒ new bit, retired bit untouched (R13.4).

Per the learned rule, the full gated `npx projen build` (compile + eslint + jest
+ cdk synth) must pass green before any PR; every new behaviour above lands with
its test in the same change.

---

## Backward compatibility & rollout

- No existing prop changes type or default. New props are all optional.
- No existing resource is renamed or recreated; the resolver adds config-secret
  keys and (optionally) one IAM grant. `PermissionsAdmin` is only instantiated
  by a consumer that opts in.
- Existing consumers (functional-self, ntrip, smart, agentl, raindancers-crew)
  synthesize byte-for-byte as before (asserted by the R1 snapshot test).
- Published as a normal `raindancers-cloudfront` minor release; horton consumes
  it per [#181](https://github.com/bwip-holdings/horton/issues/181).
