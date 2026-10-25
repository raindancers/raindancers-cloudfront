"""Regional management Lambda for the PermissionsAdmin construct.

The SOLE enforcement point for the (role, scope, assignment) authority model.
Every request runs one gate order:

  1. authN  — RS256-verify the caller's `web_identity` token against the
              published JWKS (R10.1). HMAC is the CloudFront edge's concern and
              is never used here (two-token model).
  2. authZ  — the op's required management permission is in the caller's own
              role claims, else 403 fail-closed (R10.2).
  3. invariants (server-side, R11):
       - no-escalation: a permission placed into a role must be held by the
         caller (R11.1);
       - rights-act lockout: any locked-out permission in a role body is denied
         for every caller (R11.2);
       - immutable predefined: edit/rename/delete/shadow of a predefined role is
         denied (R11.3);
       - archive-not-delete: deleting an in-use role archives it + retires its
         bit (R11.4, R13.3).
  4. mutation — written only through the injected tables (R8.3).
  5. audit    — every mutation and every denial is stamped with the acting
                principal (R12).

Config comes from env vars (this is a regional Lambda, not Lambda@Edge). boto3
is imported lazily so unit tests can patch the DynamoDB layer without AWS.
"""

import json
import logging
import os
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_JWKS_CLIENT = None
_STS = None

# Per-request assumed-role DynamoDB resource. The management Lambda carries NO
# standing table grants (two-token model); it exchanges the caller's RS256
# `web_identity` token for the estate management role via
# sts:AssumeRoleWithWebIdentity and uses THOSE scoped credentials for every
# table call in the request. A ContextVar keeps it request-local so the 11
# _ddb() call sites need no signature change and concurrent invokes never share
# credentials.
import contextvars
_REQUEST_DDB: 'contextvars.ContextVar' = contextvars.ContextVar('request_ddb', default=None)

TAG_CLAIM = 'https://aws.amazon.com/tags/principal_tags/Claims'


# --- lazy AWS accessors (patchable in tests) ---------------------------------
def _ddb():
    """The DynamoDB resource for THIS request — the assumed-role credentials set
    by assume_management_role(). Tests patch this directly; in the Lambda it is
    never the function's own role (which has no table access)."""
    res = _REQUEST_DDB.get()
    if res is None:
        # No request-scoped resource: either a test that patched _ddb, or a
        # misuse. Fail closed rather than silently fall back to standing creds.
        raise RuntimeError('no assumed-role DynamoDB resource for this request')
    return res


def _sts():
    global _STS
    if _STS is None:
        import boto3
        _STS = boto3.client('sts')
    return _STS


def assume_management_role(web_identity_token, actor):
    """Exchange the caller's RS256 `web_identity` token for the estate management
    role via sts:AssumeRoleWithWebIdentity, and return a DynamoDB resource bound
    to those scoped credentials. The Lambda holds no table grants of its own; all
    store access flows through this assumed role (R16, two-token model).

    The role ARN is injected as MANAGEMENT_ROLE_ARN. The authority tables are
    estate-level (no brand LeadingKeys), so no session tag is needed — the role's
    own permission policy scopes it to exactly the three authority tables."""
    role_arn = _cfg('MANAGEMENT_ROLE_ARN')
    import boto3
    creds = _sts().assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=f'perm-admin-{(actor or "caller")[:48]}',
        WebIdentityToken=web_identity_token,
    )['Credentials']
    return boto3.resource(
        'dynamodb',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )


def _jwks_client():
    """Cache a PyJWKClient over the consumer's published JWKS (execution-context
    reuse keeps the key fetch off the hot path). HMAC is NOT used here — the
    HMAC session cookie is the CloudFront edge's concern; behind the edge the
    caller is identified by the RS256 `web_identity` token alone."""
    global _JWKS_CLIENT
    if _JWKS_CLIENT is None:
        from jwt import PyJWKClient
        _JWKS_CLIENT = PyJWKClient(_cfg('JWKS_URI'))
    return _JWKS_CLIENT


# --- config ------------------------------------------------------------------
def _cfg(name, default=''):
    return os.environ.get(name, default)


def _json_env(name, default):
    raw = os.environ.get(name)
    return json.loads(raw) if raw else default


def _management_permissions():
    return _json_env('MANAGEMENT_PERMISSIONS', {})


def _predefined_roles():
    return _json_env('PREDEFINED_ROLES', [])


def _rights_act_lockout():
    return set(_json_env('RIGHTS_ACT_LOCKOUT', []))


# --- helpers -----------------------------------------------------------------
def _response(status, body):
    return {
        'statusCode': status,
        'headers': {'content-type': 'application/json'},
        'body': json.dumps(body),
    }


def verify_web_identity(cookie_header):
    """RS256-verify the `web_identity` token cookie against the JWKS. Returns
    `(claims, raw_token)` on success, or None.

    The two-token model: the CloudFront edge already HMAC-validated the session
    cookie before this request reached the regional API, so authN HERE reads the
    asymmetric `web_identity` token (the same token the operator API exchanges
    for a role) and verifies it against the consumer's published JWKS — no shared
    secret, no HMAC. The raw token is returned too so the handler can exchange it
    for the management role (sts:AssumeRoleWithWebIdentity). A
    missing/malformed/expired token or a bad signature returns None (-> 401).
    """
    if not cookie_header:
        return None
    cookie_name = _cfg('SESSION_COOKIE_NAME', '__Host-web_identity')
    token = None
    for part in cookie_header.split(';'):
        part = part.strip()
        if part.startswith(cookie_name + '='):
            token = part[len(cookie_name) + 1:]
            break
    if not token:
        return None
    import jwt
    try:
        signing_key = _jwks_client().get_signing_key_from_jwt(token)
        issuer = _cfg('TOKEN_ISSUER') or None
        audience = _cfg('TOKEN_AUDIENCE') or None
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            issuer=issuer,
            audience=audience,
            options={
                'require': ['exp', 'iat'],
                'verify_aud': audience is not None,
                'verify_iss': issuer is not None,
            },
        )
        return claims, token
    except Exception as exc:  # jwt.InvalidTokenError and any key-fetch failure
        logger.info(f'web_identity verification failed: {type(exc).__name__}')
        return None


def caller_permissions(claims):
    """Flatten the caller's held permission ids from their session role claims.

    The mint carries `roles` as the resolver's bitmask-per-scope structure; for
    management-permission checks we also accept a flat `permissions` list the
    consumer's resolver may include. Returns a set of permission ids.
    """
    perms = set()
    raw = claims.get('permissions')
    if isinstance(raw, list):
        perms.update(raw)
    roles = claims.get('roles')
    if isinstance(roles, list):
        perms.update(roles)
    return perms


def resolve_held_permissions(actor):
    """Resolve the caller's held permission ids from their role ASSIGNMENTS.

    The web-identity token is deliberately minimal — it carries identity (`sub`)
    and a brand tag, never permissions (the mint cannot and must not embed the
    authority model). So authZ is resolved server-side HERE, from the authority
    tables, under the caller's own assumed management role:

      1. query ASSIGNMENT_TABLE for pk=PRINCIPAL#<sub>  -> the caller's roleIds
      2. map each roleId -> its permissionIds (predefined roles from config,
         custom roles from ROLE_TABLE; archived/retired roles still grant while
         assigned)
      3. union = the caller's held permission ids

    Returns a set. An operator with no assignment holds nothing (fail-closed).
    Must run AFTER assume_management_role so the table reads use the caller's
    scoped credentials (the Lambda itself holds no standing table grants).
    """
    if not actor:
        return set()
    # roleId -> permissionIds, from predefined config first.
    role_perms = {}
    for r in _predefined_roles():
        rid = r.get('id')
        if rid:
            role_perms[rid] = set(r.get('permissionIds', []))

    assignments = _ddb().Table(_cfg('ASSIGNMENT_TABLE')).query(
        KeyConditionExpression='pk = :pk',
        ExpressionAttributeValues={':pk': f'PRINCIPAL#{actor}'},
    ).get('Items', [])

    held = set()
    role_table = _ddb().Table(_cfg('ROLE_TABLE'))
    for a in assignments:
        rid = a.get('roleId')
        if not rid:
            continue
        if rid in role_perms:
            held.update(role_perms[rid])
            continue
        # Custom role — read its permissionIds from the role table (cache it).
        item = role_table.get_item(
            Key={'pk': f'ROLE#{rid}', 'sk': f'ROLE#{rid}'}).get('Item')
        perms = set(item.get('permissionIds', [])) if item else set()
        role_perms[rid] = perms
        held.update(perms)
    return held


def audit(action, actor, target, outcome, detail=None):
    """Write an actor-stamped audit entry; log it too (R12.1, R12.2).

    Audit rows live in the role table under pk=AUDIT# so the construct needs no
    extra store; the consumer's AuditLogArchive ships the Lambda logs. A failure
    to persist the audit row is logged but never masks the operation's result.
    """
    entry = {
        'action': action, 'actor': actor, 'target': target,
        'outcome': outcome, 'ts': int(time.time()),
    }
    if detail:
        entry['detail'] = detail
    logger.info(f'AUDIT {json.dumps(entry)}')
    try:
        table = _ddb().Table(_cfg('ROLE_TABLE'))
        table.put_item(Item={
            'pk': f'AUDIT#{entry["ts"]}#{actor}',
            'sk': f'{action}#{target}',
            **entry,
        })
    except Exception as e:
        logger.error(f'Audit persist failed (non-fatal): {e}')


# --- bit registry (R13) ------------------------------------------------------
def allocate_custom_bit(scope_id, role_id):
    """Allocate the lowest free bit 0-15 in a scope's custom mask.

    A retired bit is never handed out again (R13.3). Raises when all 16 bits are
    taken (active or retired) — the role cap is 16 (from the issue).
    """
    table = _ddb().Table(_cfg('BIT_REGISTRY_TABLE'))
    taken = set()
    resp = table.query(
        KeyConditionExpression='pk = :pk',
        ExpressionAttributeValues={':pk': f'SCOPE#{scope_id}'},
    )
    for item in resp.get('Items', []):
        taken.add(int(item['bit']))
    for bit in range(16):
        if bit not in taken:
            table.put_item(Item={
                'pk': f'SCOPE#{scope_id}', 'sk': f'BIT#{bit}',
                'bit': bit, 'roleId': role_id, 'status': 'active',
            })
            return bit
    raise ValueError('custom mask full: all 16 bits allocated or retired')


def retire_custom_bit(scope_id, role_id):
    """Retire (never remove) a custom role's bit so it is never reused (R13.3)."""
    table = _ddb().Table(_cfg('BIT_REGISTRY_TABLE'))
    resp = table.query(
        KeyConditionExpression='pk = :pk',
        ExpressionAttributeValues={':pk': f'SCOPE#{scope_id}'},
    )
    for item in resp.get('Items', []):
        if item.get('roleId') == role_id and item.get('status') == 'active':
            table.update_item(
                Key={'pk': item['pk'], 'sk': item['sk']},
                UpdateExpression='SET #s = :r',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':r': 'retired'},
            )
            return int(item['bit'])
    return None


def role_in_use(role_id):
    """True if any assignment references this role (archive-not-delete, R11.4)."""
    table = _ddb().Table(_cfg('ASSIGNMENT_TABLE'))
    resp = table.query(
        IndexName=_cfg('ASSIGNMENT_ROLE_INDEX', 'roleId-index'),
        KeyConditionExpression='roleId = :r',
        ExpressionAttributeValues={':r': role_id},
        Limit=1,
    )
    return len(resp.get('Items', [])) > 0


# --- operations --------------------------------------------------------------
def _predefined_ids_and_names():
    ids, names = set(), set()
    for r in _predefined_roles():
        ids.add(r['id'])
        names.add(r['name'])
    return ids, names


def create_role(actor, held, body):
    """Create a custom role, enforcing all invariants (R11.1-R11.3, R13.2)."""
    role_id = body.get('id', '')
    name = body.get('name', '')
    scope_id = body.get('scopeId', 'ESTATE')
    permission_ids = set(body.get('permissionIds', []))

    pre_ids, pre_names = _predefined_ids_and_names()
    # Immutable predefined — no custom role may shadow a predefined id/name.
    if role_id in pre_ids or name in pre_names:
        audit('createRole', actor, role_id or name, 'denied', 'shadows predefined')
        return _response(403, {'error': 'shadows_predefined_role'})

    # Rights-act lockout — denied for every caller, unconditionally.
    locked = permission_ids & _rights_act_lockout()
    if locked:
        audit('createRole', actor, role_id, 'denied', f'rights-act lockout: {sorted(locked)}')
        return _response(403, {'error': 'rights_act_lockout'})

    # No-escalation — every permission must be held by the caller.
    escalated = permission_ids - held
    if escalated:
        audit('createRole', actor, role_id, 'denied', f'escalation: {sorted(escalated)}')
        return _response(403, {'error': 'no_escalation'})

    bit = allocate_custom_bit(scope_id, role_id)
    _ddb().Table(_cfg('ROLE_TABLE')).put_item(Item={
        'pk': f'ROLE#{role_id}', 'sk': f'ROLE#{role_id}',
        'name': name, 'scopeId': scope_id, 'mask': 'custom', 'bit': bit,
        'permissionIds': sorted(permission_ids), 'status': 'active',
    })
    audit('createRole', actor, role_id, 'ok', f'bit={bit}')
    return _response(201, {'id': role_id, 'bit': bit, 'status': 'active'})


def delete_role(actor, held, body):
    """Delete a custom role — archive-not-delete if in use (R11.3, R11.4)."""
    role_id = body.get('id', '')
    pre_ids, _ = _predefined_ids_and_names()
    if role_id in pre_ids:
        audit('deleteRole', actor, role_id, 'denied', 'predefined immutable')
        return _response(403, {'error': 'predefined_immutable'})

    table = _ddb().Table(_cfg('ROLE_TABLE'))
    existing = table.get_item(Key={'pk': f'ROLE#{role_id}', 'sk': f'ROLE#{role_id}'}).get('Item')
    if not existing:
        return _response(404, {'error': 'role_not_found'})
    scope_id = existing.get('scopeId', 'ESTATE')

    if role_in_use(role_id):
        table.update_item(
            Key={'pk': f'ROLE#{role_id}', 'sk': f'ROLE#{role_id}'},
            UpdateExpression='SET #s = :a',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':a': 'archived'},
        )
        retire_custom_bit(scope_id, role_id)
        audit('deleteRole', actor, role_id, 'archived', 'in use by >=1 assignment')
        return _response(200, {'id': role_id, 'status': 'archived'})

    retire_custom_bit(scope_id, role_id)
    table.delete_item(Key={'pk': f'ROLE#{role_id}', 'sk': f'ROLE#{role_id}'})
    audit('deleteRole', actor, role_id, 'deleted')
    return _response(200, {'id': role_id, 'status': 'deleted'})


def create_assignment(actor, held, body):
    principal = body.get('principal', '')
    role_id = body.get('roleId', '')
    scope_id = body.get('scopeId', '')
    _ddb().Table(_cfg('ASSIGNMENT_TABLE')).put_item(Item={
        'pk': f'PRINCIPAL#{principal}', 'sk': f'ROLE#{role_id}#SCOPE#{scope_id}',
        'roleId': role_id, 'scopeId': scope_id, 'principal': principal,
    })
    audit('createAssignment', actor, f'{principal}:{role_id}:{scope_id}', 'ok')
    return _response(201, {'principal': principal, 'roleId': role_id, 'scopeId': scope_id})


def delete_assignment(actor, held, body):
    principal = body.get('principal', '')
    role_id = body.get('roleId', '')
    scope_id = body.get('scopeId', '')
    _ddb().Table(_cfg('ASSIGNMENT_TABLE')).delete_item(
        Key={'pk': f'PRINCIPAL#{principal}', 'sk': f'ROLE#{role_id}#SCOPE#{scope_id}'})
    audit('deleteAssignment', actor, f'{principal}:{role_id}:{scope_id}', 'ok')
    return _response(200, {'deleted': True})


def list_roles(actor, held, body):
    resp = _ddb().Table(_cfg('ROLE_TABLE')).scan()
    roles = [i for i in resp.get('Items', []) if str(i.get('pk', '')).startswith('ROLE#')]
    return _response(200, {'roles': roles})


def list_assignments(actor, held, body):
    resp = _ddb().Table(_cfg('ASSIGNMENT_TABLE')).scan()
    return _response(200, {'assignments': resp.get('Items', [])})


def reflect_permissions(actor, held, body):
    """The caller's-own-permissions reflection endpoint the SPA calls on load.

    Returns which management operations the caller may perform, so the SPA can
    render only permitted actions (fail-closed to hidden, R9.2). The SPA
    enforces nothing — this is a convenience mirror of the server-side authZ.
    """
    mgmt = _management_permissions()
    allowed = {op: (perm in held) for op, perm in mgmt.items()}
    return _response(200, {'permissions': sorted(held), 'operations': allowed})


# op key -> (management-permission map key, handler). reflect has no gate.
_OPS = {
    ('POST', 'roles'): ('createRole', create_role),
    ('DELETE', 'roles'): ('deleteRole', delete_role),
    ('GET', 'roles'): ('listRoles', list_roles),
    ('POST', 'assignments'): ('createAssignment', create_assignment),
    ('DELETE', 'assignments'): ('deleteAssignment', delete_assignment),
    ('GET', 'assignments'): ('listAssignments', list_assignments),
}


def _route(event):
    """Extract (method, resource) from an HTTP API v2 proxy event."""
    ctx = event.get('requestContext', {}).get('http', {})
    method = ctx.get('method', event.get('httpMethod', 'GET'))
    raw_path = ctx.get('path', event.get('rawPath', '/'))
    segments = [s for s in raw_path.split('/') if s]
    resource = segments[-1] if segments else ''
    return method, resource


def handler(event, context):
    method, resource = _route(event)

    headers = {k.lower(): v for k, v in (event.get('headers') or {}).items()}
    # HTTP API payload format 2.0 delivers cookies in a top-level `cookies`
    # list, NOT in the `cookie` header (format 1.0 / direct callers use the
    # header). Read the v2 list first and fall back to the header so the handler
    # authenticates under both payload formats.
    cookie_header = headers.get('cookie')
    event_cookies = event.get('cookies')
    if not cookie_header and isinstance(event_cookies, list):
        cookie_header = '; '.join(event_cookies)
    verified = verify_web_identity(cookie_header)
    if not verified:
        return _response(401, {'error': 'invalid_session'})
    claims, web_identity_token = verified

    actor = claims.get('sub', '')
    # Permissions from the token claims, if the consumer's mint embeds any
    # (the horton web-identity mint does not — see resolve_held_permissions).
    held = caller_permissions(claims)

    # Exchange the caller's token for the estate management role and bind every
    # table call in this request to those scoped credentials. The Lambda itself
    # holds no table grants (two-token model); a failure here is fail-closed.
    try:
        _REQUEST_DDB.set(assume_management_role(web_identity_token, actor))
    except Exception as exc:
        logger.error(f'assume_management_role failed: {type(exc).__name__}')
        return _response(403, {'error': 'role_assumption_failed'})

    # Resolve the caller's held permissions from their role ASSIGNMENTS, under
    # the just-assumed management role (the token carries no permissions). Union
    # with any claim-carried permissions so a consumer whose mint DOES embed
    # them is not regressed.
    try:
        held = held | resolve_held_permissions(actor)
    except Exception as exc:
        logger.error(f'resolve_held_permissions failed: {type(exc).__name__}')
        return _response(403, {'error': 'permission_resolution_failed'})

    try:
        body = json.loads(event.get('body') or '{}')
    except Exception:
        body = {}

    if resource == 'reflect' and method == 'GET':
        return reflect_permissions(actor, held, body)

    op = _OPS.get((method, resource))
    if not op:
        return _response(404, {'error': 'unknown_operation'})

    perm_key, fn = op
    required = _management_permissions().get(perm_key)
    # authZ — fail-closed: missing required management permission => 403.
    if not required or required not in held:
        audit(perm_key, actor, resource, 'denied', 'missing management permission')
        return _response(403, {'error': 'missing_management_permission'})

    return fn(actor, held, body)
