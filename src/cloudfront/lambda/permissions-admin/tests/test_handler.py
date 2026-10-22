"""Unit tests for the PermissionsAdmin management Lambda.

Pure-stdlib `unittest` (no pytest/moto/boto3), matching scim-provisioning/tests.
Run: python3 -m unittest discover -s tests -p 'test_*.py'

A minimal in-memory DynamoDB stands in for the three injected tables via a fake
`_ddb()` resource. Sessions are real HS256 cookies signed with a known secret so
authN runs for real. Each test sets the handler's env config and resets caches.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import unittest

HANDLER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HANDLER_DIR)

import index  # noqa: E402

SECRET = 'test-session-secret'


# --- in-memory DynamoDB ------------------------------------------------------
class FakeTable:
    def __init__(self):
        self.items = {}

    @staticmethod
    def _k(key):
        return (key['pk'], key['sk'])

    def put_item(self, Item):
        self.items[(Item['pk'], Item['sk'])] = dict(Item)

    def get_item(self, Key):
        it = self.items.get(self._k(Key))
        return {'Item': dict(it)} if it else {}

    def delete_item(self, Key):
        self.items.pop(self._k(Key), None)

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues,
                    ExpressionAttributeNames=None):
        it = self.items.setdefault(self._k(Key), {'pk': Key['pk'], 'sk': Key['sk']})
        # Only SET #s = :x is used; map the alias to the value.
        names = ExpressionAttributeNames or {}
        attr = names.get('#s', 's')
        val = list(ExpressionAttributeValues.values())[0]
        it[attr] = val

    def query(self, KeyConditionExpression=None, ExpressionAttributeValues=None,
              IndexName=None, Limit=None, **kw):
        vals = ExpressionAttributeValues or {}
        out = []
        if IndexName:  # roleId-index: match on roleId attr
            role = vals.get(':r')
            out = [dict(v) for v in self.items.values() if v.get('roleId') == role]
        else:  # pk = :pk
            pk = vals.get(':pk')
            out = [dict(v) for v in self.items.values() if v.get('pk') == pk]
        if Limit:
            out = out[:Limit]
        return {'Items': out}

    def scan(self, **kw):
        return {'Items': [dict(v) for v in self.items.values()]}


class FakeDdb:
    def __init__(self):
        self.tables = {}

    def Table(self, name):
        return self.tables.setdefault(name, FakeTable())


def _cookie(sub='admin', permissions=None, exp=None):
    payload = {'sub': sub, 'permissions': permissions or [], 'exp': exp or (int(time.time()) + 3600)}

    def b64(d):
        return base64.urlsafe_b64encode(d).decode().rstrip('=')
    header_b64 = b64(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())
    payload_b64 = b64(json.dumps(payload).encode())
    sig = hmac.new(SECRET.encode(), f'{header_b64}.{payload_b64}'.encode(), hashlib.sha256).digest()
    token = f'{header_b64}.{payload_b64}.{b64(sig)}'
    return f'__Host-auth_session={token}'


def _event(method, resource, body=None, cookie=None, sub='admin', permissions=None):
    return {
        'requestContext': {'http': {'method': method, 'path': f'/admin/api/{resource}'}},
        'headers': {'cookie': cookie or _cookie(sub=sub, permissions=permissions)},
        'body': json.dumps(body) if body is not None else None,
    }


class PermissionsAdminTests(unittest.TestCase):
    def setUp(self):
        self.ddb = FakeDdb()
        index._DDB = self.ddb
        index._SESSION_SECRET = SECRET
        index._SECRETS = None
        os.environ.update({
            'ROLE_TABLE': 'roles', 'ASSIGNMENT_TABLE': 'assignments',
            'BIT_REGISTRY_TABLE': 'bits', 'ASSIGNMENT_ROLE_INDEX': 'roleId-index',
            'SESSION_COOKIE_NAME': '__Host-auth_session',
            'MANAGEMENT_PERMISSIONS': json.dumps({
                'createRole': 'mgmt.role.create', 'deleteRole': 'mgmt.role.delete',
                'listRoles': 'mgmt.role.list', 'createAssignment': 'mgmt.assign.create',
                'deleteAssignment': 'mgmt.assign.delete', 'listAssignments': 'mgmt.assign.list',
            }),
            'PREDEFINED_ROLES': json.dumps([
                {'id': 'editor', 'name': 'Editor', 'permissionIds': ['content.write'], 'bit': 0},
            ]),
            'RIGHTS_ACT_LOCKOUT': json.dumps(['danger.superuser']),
            'ESTATE_LEVEL_PERMS': json.dumps([]),
            'SCOPE_LABEL': 'scope',
        })

    def _audit_rows(self):
        return [v for v in self.ddb.Table('roles').items.values()
                if str(v.get('pk', '')).startswith('AUDIT#')]

    def test_invalid_session_401(self):
        ev = _event('GET', 'roles', cookie='__Host-auth_session=garbage')
        self.assertEqual(index.handler(ev, None)['statusCode'], 401)

    def test_missing_management_permission_denied(self):
        # Caller holds createRole perm? No. => 403 (R10.4).
        ev = _event('POST', 'roles', body={'id': 'r1'}, permissions=[])
        self.assertEqual(index.handler(ev, None)['statusCode'], 403)

    def test_no_escalation_denied(self):
        # Caller may create roles but does not hold content.write => 403 (R11.1).
        ev = _event('POST', 'roles',
                    body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['content.write']},
                    permissions=['mgmt.role.create'])
        self.assertEqual(index.handler(ev, None)['statusCode'], 403)
        self.assertEqual(json.loads(index.handler(ev, None)['body'])['error'], 'no_escalation')

    def test_rights_act_lockout_denied(self):
        # Even holding the perm, a lockout permission is denied for everyone (R11.2).
        ev = _event('POST', 'roles',
                    body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['danger.superuser']},
                    permissions=['mgmt.role.create', 'danger.superuser'])
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 403)
        self.assertEqual(json.loads(resp['body'])['error'], 'rights_act_lockout')

    def test_predefined_role_immutable(self):
        # Shadowing a predefined name on create => denied (R11.3).
        ev = _event('POST', 'roles',
                    body={'id': 'x', 'name': 'Editor', 'scopeId': 's1', 'permissionIds': []},
                    permissions=['mgmt.role.create'])
        self.assertEqual(index.handler(ev, None)['statusCode'], 403)
        # Deleting a predefined id => denied.
        ev2 = _event('DELETE', 'roles', body={'id': 'editor'}, permissions=['mgmt.role.delete'])
        self.assertEqual(index.handler(ev2, None)['statusCode'], 403)

    def test_create_role_ok_and_audited(self):
        ev = _event('POST', 'roles',
                    body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['content.write']},
                    sub='alice', permissions=['mgmt.role.create', 'content.write'])
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 201)
        body = json.loads(resp['body'])
        self.assertEqual(body['bit'], 0)
        # R12.3: a successful mutation is audited with the acting principal.
        rows = self._audit_rows()
        self.assertTrue(any(r['actor'] == 'alice' and r['action'] == 'createRole' and r['outcome'] == 'ok'
                            for r in rows))

    def test_inuse_role_archived_not_deleted(self):
        # Create r1, assign it, then delete => archived, item retained (R11.4).
        self.assertEqual(index.handler(_event('POST', 'roles',
            body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['content.write']},
            permissions=['mgmt.role.create', 'content.write']), None)['statusCode'], 201)
        self.assertEqual(index.handler(_event('POST', 'assignments',
            body={'principal': 'bob', 'roleId': 'r1', 'scopeId': 's1'},
            permissions=['mgmt.assign.create']), None)['statusCode'], 201)
        resp = index.handler(_event('DELETE', 'roles', body={'id': 'r1'},
            permissions=['mgmt.role.delete']), None)
        self.assertEqual(json.loads(resp['body'])['status'], 'archived')
        role = self.ddb.Table('roles').get_item(Key={'pk': 'ROLE#r1', 'sk': 'ROLE#r1'})['Item']
        self.assertEqual(role['status'], 'archived')  # retained, not deleted

    def test_retired_bit_not_reused(self):
        # r1 gets bit 0; delete it (not in use => hard delete + retire bit);
        # a new custom role in the same scope must get bit 1, not 0 (R13.4).
        index.handler(_event('POST', 'roles',
            body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['content.write']},
            permissions=['mgmt.role.create', 'content.write']), None)
        index.handler(_event('DELETE', 'roles', body={'id': 'r1'},
            permissions=['mgmt.role.delete']), None)
        resp = index.handler(_event('POST', 'roles',
            body={'id': 'r2', 'name': 'R2', 'scopeId': 's1', 'permissionIds': ['content.write']},
            permissions=['mgmt.role.create', 'content.write']), None)
        self.assertEqual(json.loads(resp['body'])['bit'], 1)

    def test_reflect_hides_unheld_operations(self):
        # The SPA reflection: caller holding only listRoles sees only that true.
        ev = _event('GET', 'reflect', permissions=['mgmt.role.list'])
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 200)
        ops = json.loads(resp['body'])['operations']
        self.assertTrue(ops['listRoles'])
        self.assertFalse(ops['createRole'])
        self.assertFalse(ops['deleteAssignment'])


if __name__ == '__main__':
    unittest.main()
