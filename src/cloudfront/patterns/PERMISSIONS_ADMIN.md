# Permissions Admin — a reusable authorization management construct

**Status:** SHIPPED (issue #47, branch `build/47-authz-constructs`)
**Scope:** a NEW construct in the cloudfront package, alongside
`CognitoSessionBackend` and the Scope Resolver (`SCOPE_RESOLVER.md`)
**Audience:** any consumer that owns a role/permission/assignment authority model
(horton is the first). Generic by construction — no consumer domain is baked in.

## Injected-config surface (shipped shape)

`PermissionsAdmin` names no consumer domain term; everything specific is
injected:

```ts
new PermissionsAdmin(this, 'Admin', {
  domainName,
  distribution,            // the consumer's existing CloudFront distribution
  assetBucket,             // the consumer's existing asset bucket
  pathPrefix: 'admin',     // SPA under /admin/*, API under /admin/api/*

  catalogue,               // atomic permissions (id + name)
  predefinedRoles,         // immutable named subsets, fixed predefined-mask bit
  rightsActLockout,        // permission ids never grantable through this surface
  scopeDimension,          // { label, source, estateLevelPermissionIds } — label only
  managementPermissions,   // which permission gates each admin op

  roleTable, assignmentTable, bitRegistryTable, // injected DynamoDB store refs
  callerIdentity: { sessionHmacSecretArn },      // verifies the session cookie
});
```

The **regional management Lambda is the sole enforcement point**: it HMAC-checks
the session cookie, gates each op by its `managementPermissions` entry, and
enforces no-escalation, rights-act lockout, immutable predefined roles, and
archive-not-delete server-side, owning the custom-role bit registry and an
actor-stamped audit trail. The bundled SPA reflects the caller's own permissions
and hides what they lack — it **enforces nothing**.

## Context

The Scope Resolver (`SCOPE_RESOLVER.md`) is the **read side** of an authority
model: at session mint it turns a user's assignments into scope claims and
principal tags. Something has to be the **write side** — where roles are defined
and assignments are granted in the first place. Today each consumer would build
that admin surface itself (its own SPA, its own management API, its own
no-escalation and rights-act guards), duplicating a non-trivial, security-
sensitive UI per project.

That surface is substantially the same everywhere: list/define roles as subsets
of a permission catalogue; create/rename/archive brands (or whatever the scope
dimension is); grant/revoke `(role, scope)` assignments to principals or groups;
all of it audited, and all of it guarded so an administrator cannot escalate
their own authority. Only the *catalogue* and the *store* differ by consumer.

## Decision

**Add a reusable `PermissionsAdmin` construct to the cloudfront package: it ships
the admin SPA and the management-API shell (roles, scopes, assignments), with the
authority invariants built in (no-escalation, rights-act lockout, immutable
predefined roles, archive-not-delete, audit). The consumer injects its own
permission catalogue, its assignment/role store, and its scope dimension. The
construct is domain-neutral — it manages "roles = subsets of a catalogue,
assigned at a scope" without knowing what the permissions or scopes mean.**

This is the write side; the Scope Resolver is the read side; together they are
the reusable authorization service, served from the same CloudFront front door a
consumer already uses for `CognitoSessionBackend`.

### What the construct provides (generic)

- **The admin SPA** — screens for Roles, Scopes (e.g. brands), and Assignments.
  Served through CloudFront like any other front-end in this package. Reflects
  the caller's own management permissions (fail-closed to hidden).
- **The management-API shell** — `POST/DELETE` for roles and assignments,
  `GET` listings, each operation carrying its required management permission.
- **The authority invariants, enforced server-side** (not the SPA):
  - **No-escalation** — an administrator may only put into a role permissions
    they already hold; cannot mint a role granting more than themselves.
  - **Rights-act lockout** — a configurable set of permissions
    (consumer-named) can never be added to a role through this surface.
  - **Immutable predefined roles** — consumer-supplied predefined roles cannot
    be edited, renamed, deleted, or shadowed by a custom role.
  - **Archive-not-delete** — a role in use by assignments is archived, not
    hard-deleted.
  - **Audit** — every role/assignment create/edit/archive is stamped with the
    acting principal.
- **The two-mask role model** (see horton ADR-0003.9): predefined vs custom
  role masks per scope, custom roles bit-assigned within a scope. The construct
  owns the bit-assignment registry invariant (a role bit is permanent; deleting
  a role retires its bit, never reused).

### What the consumer injects (domain-specific)

- **The permission catalogue** — the atomic permissions and their names.
- **The predefined roles** — the immutable floor (names + their permission
  subsets), and which permissions are rights-acts (the lockout set).
- **The store** — the DynamoDB tables for roles and assignments (the construct
  reads/writes through injected table references, as `CognitoSessionBackend`
  takes pool identifiers).
- **The scope dimension** — what a scope is (horton: a brand) and its source
  (the brand list), plus the estate-vs-scope split.
- **The management permissions** — which permission gates each admin operation
  (e.g. horton's `operator.manage` / `brand.manage` / `role.manage`).

### Relationship to the other two pieces

```
PermissionsAdmin (this)  —writes→  role + assignment store
                                         │
Scope Resolver            —reads→  store, at mint → scope claims + principal tags
                                         │
Consumer app (horton)     —assumes→ scoped AWS role from the minted token
```

One authority model, three constructs: admin (write), resolver (read at mint),
app enforcement (consume). All reusable; only the catalogue/store/scope are
consumer-supplied.

## Consequences

- **The admin UI is built once.** A new consumer gets roles/assignments
  management by instantiating the construct with its catalogue and store — no
  bespoke SPA, no re-implemented guards.
- **The security-sensitive invariants live in one reviewed place**, not copied
  per consumer. The no-escalation and rights-act guards are the construct's, so
  a consumer cannot forget them.
- **Domain-neutral.** The construct never names a brand, a subject, or any
  horton concept — it manages abstract roles/scopes/assignments. horton's
  meaning is entirely in the injected catalogue and store.
- **Pairs with the Scope Resolver.** Write side and read side of the same model,
  same package, same front door.

## Open

- Store contract: the exact shape of the injected role/assignment table
  interface (so the construct is store-agnostic within DynamoDB).
- SPA delivery: bundled static assets vs a consumer-provided build (likely the
  former, mirroring the package's existing front-end deployment construct).
- Whether the management API is Lambda@Edge or a regional API behind the same
  distribution.
- How the scope dimension is parameterised generically (brand today; the
  construct should not assume the word "brand").
