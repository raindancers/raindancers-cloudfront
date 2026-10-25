"""Unit tests for the PermissionsAdmin management Lambda.

Pure-stdlib `unittest` (no pytest/moto/boto3), matching scim-provisioning/tests.
Run: python3 -m unittest discover -s tests -p 'test_*.py'

A minimal in-memory DynamoDB stands in for the three injected tables. AuthN is
the RS256 `web_identity` token verified against a JWKS — real crypto is out of
scope for these behavioural tests, so `verify_web_identity` is stubbed to return
the caller's claims, and `assume_management_role` is stubbed to hand back the
in-memory DynamoDB (the two-token model's per-request assumed resource). Each
test sets the handler's env config and resets caches.
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


def _event(method, resource, body=None, sub='admin', permissions=None, bad_token=False):
    """Build an API event. The cookie value is a JSON blob the stubbed
    verify_web_identity decodes into claims (real RS256/JWKS verification is
    covered by the construct's wiring, not these behavioural tests). bad_token
    simulates a verification failure (-> 401)."""
    if bad_token:
        cookie = '__Host-web_identity=invalid'
    else:
        claims = {'sub': sub, 'permissions': permissions or [], 'exp': int(time.time()) + 3600}
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
        # restore them (a `del` of a patched name would otherwise wipe the real
        # function for every later test in the run).
        self._orig_verify = index.verify_web_identity
        self._orig_assume = index.assume_management_role
        self._orig_resolve = index.resolve_held_via_resolver

        # Stub authN: decode the claims the test embedded in the cookie, or None
        # for the invalid-token case. No real RS256/JWKS in behavioural tests.
        def fake_verify(cookie_header):
            if not cookie_header or '=invalid' in cookie_header:
                return None
            raw = cookie_header.split('__Host-web_identity=', 1)[1]
            return json.loads(raw), 'web-identity-token'
        index.verify_web_identity = fake_verify

        # Stub the token->role exchange: hand back the in-memory DynamoDB as the
        # per-request assumed resource (the real assume_role_with_web_identity is
        # construct-wiring, not handler logic).
        index.assume_management_role = lambda token, actor: self.ddb

        os.environ.update({
            'ROLE_TABLE': 'roles', 'ASSIGNMENT_TABLE': 'assignments',
            'BIT_REGISTRY_TABLE': 'bits', 'ASSIGNMENT_ROLE_INDEX': 'roleId-index',
            'SESSION_COOKIE_NAME': '__Host-web_identity',
            'JWKS_URI': 'https://example.test/.well-known/jwks.json',
            'MANAGEMENT_ROLE_ARN': 'arn:aws:iam::123456789012:role/mgmt',
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

    def tearDown(self):
        # Restore every monkeypatched module attribute (prevents a `del`/patch
        # in one test from leaking into the next).
        index.verify_web_identity = self._orig_verify
        index.assume_management_role = self._orig_assume
        index.resolve_held_via_resolver = self._orig_resolve

    def _audit_rows(self):
        return [v for v in self.ddb.Table('roles').items.values()
                if str(v.get('pk', '')).startswith('AUDIT#')]

    def test_invalid_session_401(self):
        ev = _event('GET', 'roles', bad_token=True)
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

    def test_v2_payload_cookie_in_cookies_list(self):
        # REGRESSION: behind an HTTP API with payload format 2.0, cookies arrive
        # in a top-level `cookies` list, NOT in the `cookie` header. The handler
        # must read that list, or it never sees the web_identity token and 401s
        # every real request. Before the fix this returned 401 (handler read
        # only headers.cookie, which v2 omits); after, it authenticates.
        claims = {'sub': 'admin', 'permissions': ['mgmt.role.list'],
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
        # list into a cookie header, and the real verify_web_identity splits on
        # ';' to find the session cookie by name. (The behavioural stub matches
        # by prefix, so this test keeps the session cookie LAST in the list so
        # the stub's naive split still yields valid JSON — the production split
        # is covered by the real handler logic, not this stub.)
        claims = {'sub': 'admin', 'permissions': ['mgmt.role.list'],
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
        ev = _event('GET', 'reflect', permissions=['mgmt.role.list'])
        self.assertNotIn('cookies', ev)
        self.assertEqual(index.handler(ev, None)['statusCode'], 200)

    # --- external authority-resolver hook (#63) ------------------------------
    def test_resolver_supplies_held_overriding_claim(self):
        # When the external resolver is configured, the handler uses ITS result
        # as the caller's held permissions, NOT the token claim. Here the token
        # carries NO permissions (web_identity carries none by design) but the
        # resolver returns {mgmt.role.list, content.write}, so the caller can
        # list (reflect shows it) yet an op needing a perm the resolver did NOT
        # return (mgmt.role.create) is denied. (tearDown restores the real fn.)
        index.resolve_held_via_resolver = lambda sub: {'mgmt.role.list', 'content.write'}
        reflect = index.handler(_event('GET', 'reflect', permissions=[]), None)
        self.assertEqual(reflect['statusCode'], 200)
        ops = json.loads(reflect['body'])['operations']
        self.assertTrue(ops['listRoles'])   # resolved perm, despite empty claim
        self.assertFalse(ops['createRole'])  # resolver did not grant it
        # An op needing mgmt.role.create is denied (resolver set lacks it).
        create = index.handler(_event('POST', 'roles',
            body={'id': 'r1', 'name': 'R1', 'scopeId': 's1', 'permissionIds': []},
            permissions=[]), None)
        self.assertEqual(create['statusCode'], 403)

    def test_resolver_failure_fails_closed_403(self):
        # A resolver failure is fail-closed: 403 permission_resolution_failed,
        # never a silent empty set that would deny-everything-as-if-authorized.
        def boom(sub):
            raise RuntimeError('resolver unreachable')
        index.resolve_held_via_resolver = boom
        resp = index.handler(_event('GET', 'reflect', permissions=['mgmt.role.list']), None)
        self.assertEqual(resp['statusCode'], 403)
        self.assertEqual(json.loads(resp['body'])['error'], 'permission_resolution_failed')

    def test_resolver_none_falls_back_to_claim(self):
        # When the resolver returns None (no resolver configured) the handler
        # falls back to the token claim — the no-regression path.
        index.resolve_held_via_resolver = lambda sub: None
        resp = index.handler(_event('GET', 'reflect', permissions=['mgmt.role.list']), None)
        self.assertEqual(resp['statusCode'], 200)
        self.assertTrue(json.loads(resp['body'])['operations']['listRoles'])


if __name__ == '__main__':
    unittest.main()
