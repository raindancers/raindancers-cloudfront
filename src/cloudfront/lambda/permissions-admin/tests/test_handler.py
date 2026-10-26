"""Unit tests for the PermissionsAdmin management Lambda (#195 token model).

Pure-stdlib `unittest` (no pytest/moto/boto3), matching scim-provisioning/tests.
Run: python3 -m unittest discover -s tests -p 'test_*.py'

Under #195 the estate management role's IAM policy is the authority gate, not
this handler: a caller who lacks the estate authority cannot assume the role
(assume_management_role -> 403 role_assumption_failed) and the role's scoped
credentials fence every table call. So there is NO per-request management-
permission 403 gate in the handler, and no bit registry — roles are plain sets
of permission ids. The caller's `ui_permissions` token claim drives ONLY the SPA
reflection endpoint and the server-side no-escalation invariant.

A minimal in-memory DynamoDB stands in for the injected tables. AuthN (RS256 vs
JWKS) is out of scope for these behavioural tests, so `verify_web_identity` is
stubbed to return the caller's claims, and `assume_management_role` is stubbed to
hand back the in-memory DynamoDB (the two-token model's per-request assumed
resource). Each test sets the handler's env config and resets caches.
"""

import json
import os
import sys
import time
import unittest

HANDLER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HANDLER_DIR)

import index  # noqa: E402


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


def _event(method, resource, body=None, sub='admin', ui_permissions=None, bad_token=False):
    """Build an API event. The cookie value is a JSON blob the stubbed
    verify_web_identity decodes into claims (real RS256/JWKS verification is
    covered by the construct's wiring, not these behavioural tests).

    `ui_permissions` is the token's baked-in UI/held permission set (#195); it
    drives the reflect endpoint and the no-escalation invariant. bad_token
    simulates a verification failure (-> 401)."""
    if bad_token:
        cookie = '__Host-web_identity=invalid'
    else:
        claims = {'sub': sub, 'ui_permissions': ui_permissions or [],
                  'exp': int(time.time()) + 3600}
        cookie = '__Host-web_identity=' + json.dumps(claims)
    return {
        'requestContext': {'http': {'method': method, 'path': f'/admin/api/{resource}'}},
        'headers': {'cookie': cookie},
        'body': json.dumps(body) if body is not None else None,
    }


class PermissionsAdminTests(unittest.TestCase):
    def setUp(self):
        self.ddb = FakeDdb()

        # Preserve module attributes this suite monkeypatches, so tearDown can
        # restore them.
        self._orig_verify = index.verify_web_identity
        self._orig_assume = index.assume_management_role

        # Stub authN: decode the claims the test embedded in the cookie, or None
        # for the invalid-token case. No real RS256/JWKS in behavioural tests.
        def fake_verify(cookie_header):
            if not cookie_header or '=invalid' in cookie_header:
                return None
            raw = cookie_header.split('__Host-web_identity=', 1)[1]
            return json.loads(raw), 'web-identity-token'
        index.verify_web_identity = fake_verify

        # Stub the token->role exchange: hand back the in-memory DynamoDB as the
        # per-request assumed resource. (A failed exchange -> 403 is the real
        # authority gate; stubbing it to succeed lets us test the ops behind it.)
        index.assume_management_role = lambda token, actor: self.ddb

        os.environ.update({
            'ROLE_TABLE': 'roles', 'ASSIGNMENT_TABLE': 'assignments',
            'ASSIGNMENT_ROLE_INDEX': 'roleId-index',
            'SESSION_COOKIE_NAME': '__Host-web_identity',
            'JWKS_URI': 'https://example.test/.well-known/jwks.json',
            'MANAGEMENT_ROLE_ARN': 'arn:aws:iam::123456789012:role/mgmt',
            'MANAGEMENT_PERMISSIONS': json.dumps({
                'createRole': 'mgmt.role.create', 'deleteRole': 'mgmt.role.delete',
                'listRoles': 'mgmt.role.list', 'createAssignment': 'mgmt.assign.create',
                'deleteAssignment': 'mgmt.assign.delete', 'listAssignments': 'mgmt.assign.list',
            }),
            'PREDEFINED_ROLES': json.dumps([
                {'id': 'editor', 'name': 'Editor', 'permissionIds': ['content.write']},
            ]),
            'RIGHTS_ACT_LOCKOUT': json.dumps(['danger.superuser']),
            'ESTATE_LEVEL_PERMS': json.dumps([]),
            'SCOPE_LABEL': 'scope',
        })

    def tearDown(self):
        index.verify_web_identity = self._orig_verify
        index.assume_management_role = self._orig_assume

    def _audit_rows(self):
        return [v for v in self.ddb.Table('roles').items.values()
                if str(v.get('pk', '')).startswith('AUDIT#')]

    def test_invalid_session_401(self):
        ev = _event('GET', 'roles', bad_token=True)
        self.assertEqual(index.handler(ev, None)['statusCode'], 401)

    def test_role_assumption_failure_denied_403(self):
        # The authority gate under #195: if the caller cannot assume the estate
        # management role, the request is denied 403 before any op runs — this
        # replaced the old per-request permission-set 403 gate.
        def boom(token, actor):
            raise RuntimeError('AccessDenied: not entitled to assume estate role')
        index.assume_management_role = boom
        resp = index.handler(_event('POST', 'roles', body={'id': 'r1'}), None)
        self.assertEqual(resp['statusCode'], 403)
        self.assertEqual(json.loads(resp['body'])['error'], 'role_assumption_failed')

    def test_no_handler_permission_gate_for_authorized_caller(self):
        # #195: the handler no longer denies on a management-permission set
        # check. A caller who successfully assumes the role (stubbed) reaches the
        # op regardless of their ui_permissions claim — authZ was the role policy.
        # A create with no permissionIds (nothing to escalate) succeeds.
        ev = _event('POST', 'roles', body={'id': 'r1', 'name': 'R1', 'scopeId': 's1'},
                    ui_permissions=[])
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 201)

    def test_no_escalation_denied(self):
        # A caller may not place into a role a permission they do not hold
        # (server-side invariant; held = token ui_permissions). => 403.
        ev = _event('POST', 'roles',
                    body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['content.write']},
                    ui_permissions=[])
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 403)
        self.assertEqual(json.loads(resp['body'])['error'], 'no_escalation')

    def test_rights_act_lockout_denied(self):
        # A rights-act lockout permission is denied for everyone, even a caller
        # who holds it.
        ev = _event('POST', 'roles',
                    body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['danger.superuser']},
                    ui_permissions=['danger.superuser'])
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 403)
        self.assertEqual(json.loads(resp['body'])['error'], 'rights_act_lockout')

    def test_predefined_role_immutable(self):
        # Shadowing a predefined name on create => denied.
        ev = _event('POST', 'roles',
                    body={'id': 'x', 'name': 'Editor', 'scopeId': 's1', 'permissionIds': []},
                    ui_permissions=['content.write'])
        self.assertEqual(index.handler(ev, None)['statusCode'], 403)
        # Deleting a predefined id => denied.
        ev2 = _event('DELETE', 'roles', body={'id': 'editor'})
        self.assertEqual(index.handler(ev2, None)['statusCode'], 403)

    def test_create_role_plain_set_no_bit(self):
        # #195: roles are plain permission sets — the response carries no `bit`
        # and the stored item carries no bit/mask.
        ev = _event('POST', 'roles',
                    body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['content.write']},
                    sub='alice', ui_permissions=['content.write'])
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 201)
        body = json.loads(resp['body'])
        self.assertEqual(body, {'id': 'r1', 'status': 'active'})
        self.assertNotIn('bit', body)
        stored = self.ddb.Table('roles').get_item(Key={'pk': 'ROLE#r1', 'sk': 'ROLE#r1'})['Item']
        self.assertNotIn('bit', stored)
        self.assertNotIn('mask', stored)
        self.assertEqual(stored['permissionIds'], ['content.write'])
        # A successful mutation is audited with the acting principal.
        rows = self._audit_rows()
        self.assertTrue(any(r['actor'] == 'alice' and r['action'] == 'createRole'
                            and r['outcome'] == 'ok' for r in rows))

    def test_inuse_role_archived_not_deleted(self):
        # Create r1, assign it, then delete => archived, item retained.
        self.assertEqual(index.handler(_event('POST', 'roles',
            body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['content.write']},
            ui_permissions=['content.write']), None)['statusCode'], 201)
        self.assertEqual(index.handler(_event('POST', 'assignments',
            body={'principal': 'bob', 'roleId': 'r1', 'scopeId': 's1'}), None)['statusCode'], 201)
        resp = index.handler(_event('DELETE', 'roles', body={'id': 'r1'}), None)
        self.assertEqual(json.loads(resp['body'])['status'], 'archived')
        role = self.ddb.Table('roles').get_item(Key={'pk': 'ROLE#r1', 'sk': 'ROLE#r1'})['Item']
        self.assertEqual(role['status'], 'archived')  # retained, not deleted

    def test_delete_unused_role_hard_deletes(self):
        # A role with no assignment is hard-deleted (no bit to retire anymore).
        index.handler(_event('POST', 'roles',
            body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': ['content.write']},
            ui_permissions=['content.write']), None)
        resp = index.handler(_event('DELETE', 'roles', body={'id': 'r1'}), None)
        self.assertEqual(json.loads(resp['body'])['status'], 'deleted')
        self.assertEqual(
            self.ddb.Table('roles').get_item(Key={'pk': 'ROLE#r1', 'sk': 'ROLE#r1'}), {})

    def test_reflect_returns_token_ui_permissions(self):
        # The SPA reflection returns the caller's ui_permissions from the token
        # and mirrors which ops they map to — a UI convenience, no authZ.
        ev = _event('GET', 'reflect', ui_permissions=['mgmt.role.list'])
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 200)
        payload = json.loads(resp['body'])
        self.assertEqual(payload['permissions'], ['mgmt.role.list'])
        ops = payload['operations']
        self.assertTrue(ops['listRoles'])
        self.assertFalse(ops['createRole'])
        self.assertFalse(ops['deleteAssignment'])

    def test_reflect_empty_ui_permissions(self):
        # No ui_permissions claim -> empty reflection, every op hidden.
        ev = _event('GET', 'reflect', ui_permissions=[])
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 200)
        payload = json.loads(resp['body'])
        self.assertEqual(payload['permissions'], [])
        self.assertTrue(all(v is False for v in payload['operations'].values()))

    def test_v2_payload_cookie_in_cookies_list(self):
        # REGRESSION: behind an HTTP API with payload format 2.0, cookies arrive
        # in a top-level `cookies` list, NOT in the `cookie` header. The handler
        # must read that list, or it never sees the web_identity token and 401s.
        claims = {'sub': 'admin', 'ui_permissions': ['mgmt.role.list'],
                  'exp': int(time.time()) + 3600}
        ev = {
            'requestContext': {'http': {'method': 'GET', 'path': '/admin/api/reflect'}},
            'cookies': ['__Host-web_identity=' + json.dumps(claims)],
            'headers': {},
            'body': None,
        }
        resp = index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 200,
                         'v2 cookies list must authenticate (payload format 2.0)')

    def test_v2_multiple_cookies_in_list(self):
        # A v2 `cookies` list carrying several cookies: the handler joins the
        # list into a cookie header (session cookie kept last so the behavioural
        # stub's naive split still yields valid JSON).
        claims = {'sub': 'admin', 'ui_permissions': ['mgmt.role.list'],
                  'exp': int(time.time()) + 3600}
        ev = {
            'requestContext': {'http': {'method': 'GET', 'path': '/admin/api/reflect'}},
            'cookies': ['other=1', 'csrf=abc',
                        '__Host-web_identity=' + json.dumps(claims)],
            'headers': {},
            'body': None,
        }
        self.assertEqual(index.handler(ev, None)['statusCode'], 200)

    def test_header_cookie_still_works(self):
        # Fallback: a `cookie` header (payload format 1.0 / direct callers) must
        # still authenticate when no `cookies` list is present.
        ev = _event('GET', 'reflect', ui_permissions=['mgmt.role.list'])
        self.assertNotIn('cookies', ev)
        self.assertEqual(index.handler(ev, None)['statusCode'], 200)


if __name__ == '__main__':
    unittest.main()
