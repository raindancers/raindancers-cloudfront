"""Regional management Lambda for the PermissionsAdmin construct.

The SOLE enforcement point for the (role, scope, assignment) authority model.
Every request runs one gate order:

  1. authN  — HMAC-verify the session cookie against the injected secret (R10.1).
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

import base64
import hashlib
import hmac
import json
import logging
import os
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_DDB = None
_SECRETS = None
_SESSION_SECRET = None

TAG_CLAIM = 'https://aws.amazon.com/tags/principal_tags/Claims'


# --- lazy AWS accessors (patchable in tests) ---------------------------------
def _ddb():
    global _DDB
    if _DDB is None:
        import boto3
        _DDB = boto3.resource('dynamodb')
    return _DDB


def _session_secret():
    global _SECRETS, _SESSION_SECRET
    if _SESSION_SECRET is not None:
        return _SESSION_SECRET
    arn = os.environ.get('SESSION_HMAC_SECRET_ARN', '')
    if not arn:
        _SESSION_SECRET = ''
        return _SESSION_SECRET
    if _SECRETS is None:
        import boto3
        _SECRETS = boto3.client('secretsmanager')
    _SESSION_SECRET = _SECRETS.get_secret_value(SecretId=arn).get('SecretString', '')
    return _SESSION_SECRET


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
def _b64url_decode(data):
    return base64.urlsafe_b64decode(data + '=' * (-len(data) % 4))


def _response(status, body):
    return {
        'statusCode': status,
        'headers': {'content-type': 'application/json'},
        'body': json.dumps(body),
    }


def verify_session(cookie_header):
    """HMAC-verify the __Host-auth_session cookie. Returns claims dict or None.

    The cookie is a `header.payload.sig` HS256 token signed with the session
    HMAC secret (the same secret the mint Lambda uses). A bad signature, a
    malformed token, or an expired token returns None (-> 401).
    """
    if not cookie_header:
        return None
    cookie_name = _cfg('SESSION_COOKIE_NAME', '__Host-auth_session')
    token = None
    for part in cookie_header.split(';'):
        part = part.strip()
        if part.startswith(cookie_name + '='):
            token = part[len(cookie_name) + 1:]
            break
    if not token:
        return None
    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
    except ValueError:
        return None
    secret = _session_secret()
    expected = hmac.new(secret.encode(), f'{header_b64}.{payload_b64}'.encode(), hashlib.sha256).digest()
    actual = _b64url_decode(sig_b64)
    if not hmac.compare_digest(expected, actual):
        return None
    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None
    if claims.get('exp') is not None and int(time.time()) >= int(claims['exp']):
        return None
    return claims


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
    claims = verify_session(headers.get('cookie'))
    if not claims:
        return _response(401, {'error': 'invalid_session'})

    actor = claims.get('sub', '')
    held = caller_permissions(claims)

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
