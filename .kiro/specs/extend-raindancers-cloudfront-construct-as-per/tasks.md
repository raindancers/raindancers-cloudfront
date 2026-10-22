# Tasks — Extend raindancers-cloudfront: Scope Resolver + Permissions Admin

Implements `design.md` against `requirements.md` for
[issue #47](https://github.com/raindancers/raindancers-cloudfront/issues/47).

Rules in force (from learned corrections):
- Every behaviour lands with a test in the same change.
- The full gated `npx projen build` (compile + eslint + jest + cdk synth) must
  pass green before the PR is opened or updated — never a bare `npx projen test`.
- Bot-authored PR from the first commit; worktree outside `~/.kiro/crew`.

Order: Scope Resolver first (small, additive, unblocks horton's read path), then
PermissionsAdmin (larger, new construct), then docs + release.

---

## Phase A — Scope Resolver (extends `CognitoSessionBackend`)

- [ ] 1. Add resolver props to the CDK surface
  - Add `ScopeResolverConfig` interface (`endpointUrl`, `sharedSecretArn?`,
    `timeoutSeconds?`) and `scopeResolver?` + `scopeTokenMaxBytes?` (default
    7168) to `CognitoSessionBackendProps` in
    `src/cloudfront/patterns/cognitoSessionBackend.ts`.
  - Export `ScopeResolverConfig` from the patterns barrel.
  - _Requirements: R1, R5.1_

- [ ] 2. Plumb resolver config into the config secret and IAM
  - In `src/cloudfront/auth/cognitoAuthSecretManager.ts`, write
    `scope_resolver_url`, `scope_resolver_secret_arn`, `scope_resolver_timeout`,
    and `scope_token_max_bytes` into the config secret.
  - When `sharedSecretArn` is set, grant the mint Lambda role
    `secretsmanager:GetSecretValue` on that ARN (mirror the identity-hook grant).
  - Leave all keys absent/empty when `scopeResolver` is unset.
  - _Requirements: R1.1, R1.2, R2.1_

- [ ] 3. Implement the resolver call + merge in the mint Lambda
  - In `src/cloudfront/lambda/cognito-customui-session/index.py` add
    `call_scope_resolver(url, secret, identity, timeout)` and
    `get_scope_resolver_secret()` (cached), modelled on `call_identity_hook` /
    `get_hook_secret`.
  - At the `session_payload` build point (after the `cognito:groups -> roles`
    copy), call the resolver when `scope_resolver_url` is set; merge whitelisted
    role claims as claims and whitelisted scope values into the
    `https://aws.amazon.com/tags/principal_tags/Claims` tag in the pre-token
    `:k=v:` shape.
  - Fail closed on timeout / non-2xx / malformed body → `503 scope_unavailable`,
    no `Set-Cookie`.
  - _Requirements: R2.1, R2.2, R2.3, R3.1, R3.2, R4.1, R4.2, R4.3_

- [ ] 4. Implement the token size guard
  - Compute the assembled token size (header + payload + HS256 sig segment)
    before building `cookie_value`; if it exceeds `scope_token_max_bytes`, log
    and return `500 scope_token_too_large` with no cookie. Never truncate.
  - _Requirements: R5.2_

- [ ] 5. Python unit tests for the resolver (mint Lambda)
  - In `src/cloudfront/lambda/cognito-customui-session/tests/` add
    `test_scope_resolver.py` (new test dir mirrors `scim-provisioning/tests`):
    - `test_mint_unchanged_without_resolver` (R1).
    - `test_resolver_claims_and_tags_merged` (R2).
    - `test_non_whitelisted_dropped` — non-whitelisted absent, whitelisted
      present, mint succeeds (R3).
    - `test_resolver_timeout_fails_closed`, `test_resolver_non2xx_fails_closed`
      (R4).
    - `test_oversize_token_refused` (R5).
  - Patch `boto3`/`urllib` via lazy accessors; no module-scope boto3 import.
  - _Requirements: R1.3, R2.4, R3.3, R4.4, R5.3_

- [ ] 6. CDK assertion tests for the resolver props
  - In `test/cognito-session-backend.test.ts`:
    - snapshot/assert: backend WITHOUT `scopeResolver` emits the unchanged
      config secret (no resolver keys) — proves backward compatibility (R1.3).
    - with `scopeResolver`: config secret carries `scope_resolver_url` and the
      `GetSecretValue` grant exists when `sharedSecretArn` is set.
  - _Requirements: R1.1, R1.3, R2.1_

---

## Phase B — `PermissionsAdmin` construct (new, write side)

- [ ] 7. Define the construct's public types (domain-neutral)
  - New file `src/cloudfront/patterns/permissionsAdmin.ts`: `PermissionsAdminProps`,
    `PermissionCatalogue`, `PredefinedRole`, `ScopeDimension`, `ScopeSource`,
    `ManagementPermissionMap`, `CallerIdentityConfig`.
  - No `brand`/`subject`/horton term in any identifier; scope meaning only via
    `ScopeDimension.label`.
  - _Requirements: R7.1, R7.2, R8.1, R8.2, R8.4, R8.5_

- [ ] 8. Scaffold the regional management API + Lambda
  - In `permissionsAdmin.ts`, create an API Gateway HTTP API + a regional Python
    Lambda (`src/cloudfront/lambda/permissions-admin/index.py`), wired to the
    injected `roleTable`, `assignmentTable`, `bitRegistryTable` with least-priv
    grants (read/write only what each op needs).
  - Add the `/<prefix>/api/*` CloudFront behaviour pointing at the HTTP API and
    the `/<prefix>/*` behaviour serving the asset bucket.
  - _Requirements: R8.3, R10.1, R14.2_

- [ ] 9. Implement authN + authZ in the management Lambda
  - Verify the `__Host-auth_session` HMAC cookie (reuse the package's session
    verification helper); 401 on invalid.
  - Resolve each op's required permission from `managementPermissions`; confirm
    the caller's own role claims include it, else 403 (fail-closed).
  - _Requirements: R10.1, R10.2_

- [ ] 10. Implement the authority invariants (server-side)
  - No-escalation: every permission placed into a role must be a subset of the
    caller's held permissions, else 403.
  - Rights-act lockout: any permission in `rightsActLockout` in a role body →
    denied for every caller.
  - Immutable predefined: reject edit/rename/delete/shadow of predefined roles.
  - Archive-not-delete: deleting a role referenced by ≥1 assignment sets
    `status=archived` (via the assignment GSI "role in use?" check).
  - _Requirements: R11.1, R11.2, R11.3, R11.4_

- [ ] 11. Implement the two-mask bit registry
  - Allocate the lowest free bit 0–15 in a scope's custom mask; fail allocation
    when all 16 bits are taken (active or retired).
  - Retire (never remove, never reuse) a custom role's bit on archive/delete.
  - _Requirements: R13.1, R13.2, R13.3_

- [ ] 12. Implement audit on every mutation and denial
  - Stamp each create/edit/archive with the acting principal (`sub`), op,
    target, and timestamp, written via `AuditLogArchive`; log denials too.
  - _Requirements: R12.1, R12.2_

- [ ] 13. Build and bundle the admin SPA
  - Vite SPA under `src/cloudfront/patterns/permissions-admin-spa/` with Roles,
    Scopes (read-only from the injected source), Assignments screens.
  - On load, call the caller's-own-permissions reflection endpoint and render
    only permitted actions — fail-closed to hidden.
  - Deploy via `ViteFrontendDeployment` to `/<prefix>/` on the injected
    distribution/bucket.
  - _Requirements: R9.1, R9.2, R9.3, R14.1_

- [ ] 14. Export the construct
  - Add `export * from './permissionsAdmin';` to
    `src/cloudfront/patterns/index.ts`.
  - _Requirements: R7.1_

- [ ] 15. Python unit tests for the management Lambda
  - In `src/cloudfront/lambda/permissions-admin/tests/test_handler.py`:
    - `test_no_escalation_denied` (R11.1).
    - `test_rights_act_lockout_denied` (R11.2).
    - `test_predefined_role_immutable` — edit/rename/delete/shadow (R11.3).
    - `test_inuse_role_archived_not_deleted` (R11.4).
    - `test_missing_management_permission_denied` (R10.4).
    - `test_mutation_audited_with_principal` (R12.3).
    - `test_retired_bit_not_reused` (R13.4).
  - Lazy boto3 accessor; patch DynamoDB in tests.
  - _Requirements: R10.4, R11.5, R12.3, R13.4_

- [ ] 16. CDK assertion tests for the construct
  - New `test/permissions-admin.test.ts`:
    - SPA deployment targets the injected bucket/distribution under the prefix
      (R14.3).
    - `/<prefix>/api/*` routes to the regional API; `/<prefix>/*` to S3.
    - no synthesized logical id or prop value contains `brand`/`subject` (R7.3).
    - a grant exists for each injected table with only the needed actions.
  - _Requirements: R7.3, R14.3_

---

## Phase C — Build, docs, release

- [ ] 17. Wire the new Python Lambda bundle into projen
  - In `.projenrc.ts`, add `permissions-admin` (and, if it needs its own deps,
    `cognito-customui-session` already bundles) to `lambdaBundles` with the
    correct Python version; run `npx projen` to regenerate.
  - _Requirements: R10.1, R14.1_

- [ ] 18. Update construct documentation
  - In `README.md` and the two pattern docs, document: `scopeResolver` /
    `scopeTokenMaxBytes` usage, the resolver HTTP contract, that
    `session_ttl_seconds` is the revocation window (R6.2), and the
    `PermissionsAdmin` injected-config surface. Flip both pattern docs' status
    from PROPOSED toward the shipped shape.
  - _Requirements: R6.2_

- [ ] 19. Full gated build + open the bot-authored PR
  - Run the full `npx projen build` green locally (compile + eslint + jest +
    cdk synth).
  - Commit and push a feature branch from a worktree outside `~/.kiro/crew`
    (bot-authored from the first commit), open the PR to
    `raindancers/raindancers-cloudfront`, and add `mrpackethead` as a requested
    reviewer via REST.
  - _Requirements: all (the gated build is the straight-cutover safety gate)_
