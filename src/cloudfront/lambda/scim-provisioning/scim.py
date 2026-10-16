"""
SCIM 2.0 lifecycle + discovery routing (RFC 7643 / 7644 subset used by IdP
provisioning). Pure request/response logic over the `store` module; no auth here
(the dispatcher authenticates before calling in).
"""

import json
import re
import uuid

import store

SCIM_CONTENT = 'application/scim+json'
USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User'
GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group'
LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
PATCHOP_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error'


def _resp(status, body):
    return {
        'statusCode': status,
        'headers': {'content-type': SCIM_CONTENT},
        'body': json.dumps(body) if not isinstance(body, str) else body,
    }


def _no_content():
    return {'statusCode': 204, 'headers': {'content-type': SCIM_CONTENT}, 'body': ''}


def scim_error(status, detail, scim_type=None):
    body = {'schemas': [ERROR_SCHEMA], 'status': str(status), 'detail': detail}
    if scim_type:
        body['scimType'] = scim_type
    return body


def _body(event):
    raw = event.get('body') or '{}'
    if event.get('isBase64Encoded'):
        import base64
        raw = base64.b64decode(raw).decode('utf-8')
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return {}


def _query_params(event):
    return event.get('queryStringParameters') or {}


# ------------------------------------------------------------ resource rendering

def _user_resource(item):
    groups = sorted(item.get('groupIds', []) or [])
    return {
        'schemas': [USER_SCHEMA],
        'id': item['scimId'],
        'externalId': item.get('externalId'),
        'userName': item.get('userName'),
        'displayName': item.get('displayName') or None,
        'active': bool(item.get('active', False)),
        'groups': [{'value': g} for g in groups],
        'meta': {'resourceType': 'User', 'lastModified': item.get('updatedAt')},
    }


def _group_resource(item):
    return {
        'schemas': [GROUP_SCHEMA],
        'id': item['groupId'],
        'displayName': item.get('displayName') or None,
        'meta': {'resourceType': 'Group', 'lastModified': item.get('updatedAt')},
    }


def _list_response(resources):
    return {
        'schemas': [LIST_SCHEMA],
        'totalResults': len(resources),
        'startIndex': 1,
        'itemsPerPage': len(resources),
        'Resources': resources,
    }


# ------------------------------------------------------------ users

# Only equality on userName or externalId is supported (the subset Entra uses to
# match-before-create). Anything else is a 400 invalidFilter, by design.
_FILTER_RE = re.compile(r'^\s*(userName|externalId)\s+eq\s+"([^"]*)"\s*$', re.IGNORECASE)


def _users_collection(method, event):
    if method == 'POST':
        body = _body(event)
        external_id = body.get('externalId')
        if not external_id:
            return _resp(400, scim_error(400, 'externalId is required', 'invalidValue'))
        scim_id = str(uuid.uuid4())
        group_ids = [g.get('value') for g in body.get('groups', []) if g.get('value')]
        store.put_user(
            external_id=external_id,
            scim_id=scim_id,
            user_name=body.get('userName'),
            display_name=body.get('displayName'),
            active=body.get('active', True),
            group_ids=group_ids,
        )
        item = store.get_user_by_external_id(external_id)
        return _resp(201, _user_resource(item))

    if method == 'GET':
        qp = _query_params(event)
        flt = qp.get('filter')
        if not flt:
            # Unbounded list is not part of the provisioning subset we support.
            return _resp(400, scim_error(400, 'a filter is required', 'invalidFilter'))
        m = _FILTER_RE.match(flt)
        if not m:
            return _resp(400, scim_error(400, 'only userName eq / externalId eq is supported', 'invalidFilter'))
        attr, value = m.group(1).lower(), m.group(2)
        item = (store.get_user_by_user_name(value) if attr == 'username'
                else store.get_user_by_external_id(value))
        resources = [_user_resource(item)] if item else []
        return _resp(200, _list_response(resources))

    return _resp(405, scim_error(405, 'method not allowed'))


def _users_item(method, scim_id, event):
    if method == 'GET':
        item = store.get_user_by_scim_id(scim_id)
        return _resp(200, _user_resource(item)) if item else _resp(404, scim_error(404, 'user not found'))

    if method == 'PUT':
        existing = store.get_user_by_scim_id(scim_id)
        if not existing:
            return _resp(404, scim_error(404, 'user not found'))
        body = _body(event)
        group_ids = [g.get('value') for g in body.get('groups', []) if g.get('value')]
        store.put_user(
            external_id=existing['externalId'],
            scim_id=scim_id,
            user_name=body.get('userName', existing.get('userName')),
            display_name=body.get('displayName', existing.get('displayName')),
            active=body.get('active', existing.get('active', True)),
            group_ids=group_ids,
        )
        return _resp(200, _user_resource(store.get_user_by_scim_id(scim_id)))

    if method == 'PATCH':
        body = _body(event)
        active = _extract_active_patch(body)
        if active is None:
            # We only honour the active replace op (the deactivation path).
            existing = store.get_user_by_scim_id(scim_id)
            return _resp(200, _user_resource(existing)) if existing else _resp(404, scim_error(404, 'user not found'))
        item = store.set_user_active_by_scim_id(scim_id, active)
        return _resp(200, _user_resource(item)) if item else _resp(404, scim_error(404, 'user not found'))

    if method == 'DELETE':
        return _no_content() if store.delete_user_by_scim_id(scim_id) else _resp(404, scim_error(404, 'user not found'))

    return _resp(405, scim_error(405, 'method not allowed'))


def _extract_active_patch(body):
    """Return the boolean target of a `replace active` op, or None if absent."""
    for op in body.get('Operations', []):
        if (op.get('op') or '').lower() != 'replace':
            continue
        path = (op.get('path') or '').lower()
        val = op.get('value')
        if path == 'active':
            return _as_bool(val)
        if path == '' and isinstance(val, dict) and 'active' in val:
            return _as_bool(val['active'])
    return None


def _as_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() == 'true'
    return bool(v)


# ------------------------------------------------------------ groups

def _groups_collection(method, event):
    if method == 'POST':
        body = _body(event)
        group_id = body.get('externalId') or body.get('id') or str(uuid.uuid4())
        store.put_group(group_id, body.get('displayName'))
        # Honour an initial member list if present.
        for m in body.get('members', []):
            if m.get('value'):
                store.add_member(group_id, m['value'])
        return _resp(201, _group_resource(store.get_group(group_id)))
    return _resp(405, scim_error(405, 'method not allowed'))


def _groups_item(method, group_id, event):
    if method == 'GET':
        item = store.get_group(group_id)
        return _resp(200, _group_resource(item)) if item else _resp(404, scim_error(404, 'group not found'))

    if method == 'PATCH':
        if not store.get_group(group_id):
            return _resp(404, scim_error(404, 'group not found'))
        body = _body(event)
        for op in body.get('Operations', []):
            name = (op.get('op') or '').lower()
            path = (op.get('path') or '').lower()
            if path == 'displayname':
                store.set_group_display_name(group_id, op.get('value'))
                continue
            if path == 'members' or path == '':
                for member in _member_values(op.get('value')):
                    if name == 'add':
                        store.add_member(group_id, member)
                    elif name == 'remove':
                        store.remove_member(group_id, member)
        return _resp(200, _group_resource(store.get_group(group_id)))

    if method == 'PUT':
        if not store.get_group(group_id):
            return _resp(404, scim_error(404, 'group not found'))
        body = _body(event)
        if 'displayName' in body:
            store.set_group_display_name(group_id, body.get('displayName'))
        return _resp(200, _group_resource(store.get_group(group_id)))

    if method == 'DELETE':
        return _no_content() if store.delete_group(group_id) else _resp(404, scim_error(404, 'group not found'))

    return _resp(405, scim_error(405, 'method not allowed'))


def _member_values(value):
    """A PATCH members value may be a list of {value:..} or a single dict."""
    if isinstance(value, list):
        return [m.get('value') for m in value if isinstance(m, dict) and m.get('value')]
    if isinstance(value, dict) and value.get('value'):
        return [value['value']]
    return []


# ------------------------------------------------------------ discovery

def _service_provider_config():
    return {
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
        'patch': {'supported': True},
        'bulk': {'supported': False, 'maxOperations': 0, 'maxPayloadSize': 0},
        'filter': {'supported': True, 'maxResults': 1},
        'changePassword': {'supported': False},
        'sort': {'supported': False},
        'etag': {'supported': False},
        'authenticationSchemes': [{
            'type': 'oauthbearertoken',
            'name': 'OAuth Bearer Token',
            'description': 'Short-lived OAuth 2.0 bearer access token obtained from the token endpoint.',
            'primary': True,
        }],
        'meta': {'resourceType': 'ServiceProviderConfig'},
    }


def _schemas():
    return _list_response([
        {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
            'id': USER_SCHEMA,
            'name': 'User',
            'description': 'SCIM core User',
        },
        {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
            'id': GROUP_SCHEMA,
            'name': 'Group',
            'description': 'SCIM core Group',
        },
    ])


def _resource_types():
    return _list_response([
        {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
            'id': 'User', 'name': 'User', 'endpoint': '/Users', 'schema': USER_SCHEMA,
        },
        {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
            'id': 'Group', 'name': 'Group', 'endpoint': '/Groups', 'schema': GROUP_SCHEMA,
        },
    ])


# ------------------------------------------------------------ dispatch

def dispatch(method, path, scim_base, event):
    rel = path[len(scim_base):] or '/'
    if not rel.startswith('/'):
        rel = '/' + rel

    # Discovery
    if method == 'GET' and rel == '/ServiceProviderConfig':
        return _resp(200, _service_provider_config())
    if method == 'GET' and rel == '/Schemas':
        return _resp(200, _schemas())
    if method == 'GET' and rel == '/ResourceTypes':
        return _resp(200, _resource_types())

    # Users
    if rel == '/Users':
        return _users_collection(method, event)
    if rel.startswith('/Users/'):
        return _users_item(method, rel[len('/Users/'):], event)

    # Groups
    if rel == '/Groups':
        return _groups_collection(method, event)
    if rel.startswith('/Groups/'):
        return _groups_item(method, rel[len('/Groups/'):], event)

    return _resp(404, scim_error(404, 'not found'))
