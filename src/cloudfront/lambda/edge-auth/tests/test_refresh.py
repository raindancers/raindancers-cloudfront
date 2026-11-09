"""Unit tests for the silent refresh route (/oauth2/refresh).

``handle_refresh`` renews an expired-but-validly-signed session: it loads the
stored Entra refresh token, exchanges it, and re-mints BOTH the session and the
RS256 web_identity cookies through the shared ``_remint_session``. Collaborators
(config, DynamoDB, Entra, resolver hook, KMS mint) are stubbed.
"""
import base64
import json
import os
import sys
import time
import types
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_scope_switch import mint, HMAC_SECRET, _make_session_cookie, _request  # noqa: E402


def _payload_of(cookie_header_value, name):
    token = cookie_header_value.split(f'{name}=', 1)[1].split(';', 1)[0]
    p = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))


class RefreshHandlerTests(unittest.TestCase):
    def setUp(self):
        mint.HMAC_SECRET = HMAC_SECRET
        mint.CONFIG = {
            'hmac_key': HMAC_SECRET,
            'web_identity_signing_key_id': 'key-123',
            'post_auth_hook_url': 'https://resolver.example/invoke',
            'enable_refresh': 'true',
            'azure_tenant_id': 'tenant',
            'azure_client_id': 'client',
            'allowed_domains': json.dumps(['admin.example.com']),
            'jwt_claims_whitelist': json.dumps([
                'sub', 'exp', 'iss', 'idp', 'preferred_username',
                'ui_permissions', 'scope', 'scopes', mint.PRINCIPAL_TAGS_CLAIM,
            ]),
            'cookie_domain': 'admin.example.com',
            'dynamodb_table_name': 'sessions',
        }
        self._saved = (mint.web_identity.is_enabled, mint.web_identity.mint_web_identity_token,
                       mint.dynamodb, mint.urllib.request.urlopen, mint.get_federated_token)
        mint.web_identity.is_enabled = lambda cfg: bool(cfg.get('web_identity_signing_key_id'))
        mint.web_identity.mint_web_identity_token = lambda *a, **k: 'wi.token.value'
        mint.get_federated_token = lambda aud: 'assertion'

        self.calls = []
        self.stored = {'Item': {'refresh_token': {'S': 'old-refresh'}, 'user_id': {'S': 'u1'},
                                'customer_id': {'S': ''}}}
        outer = self

        def get_item(**kw):
            outer.calls.append(('get', kw))
            return outer.stored
        mint.dynamodb = types.SimpleNamespace(
            get_item=get_item,
            update_item=lambda **kw: self.calls.append(('update', kw)),
            put_item=lambda **kw: self.calls.append(('put', kw)),
            delete_item=lambda **kw: self.calls.append(('delete', kw)),
        )

        self.hook_result = {
            'additional_claims': {'ui_permissions': ['subject.read'], 'scope': 'brand:acme'},
            'principal_tags': {'brand': 'acme', 'subject.read': '1'},
        }
        self.entra = {'expires_in': 3600, 'refresh_token': 'new-refresh'}
        self.entra_error = None
        self.hook_requests = []

        class _Resp:
            def __init__(self, body):
                self._b = json.dumps(body).encode()
            def read(self):
                return self._b
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def urlopen(req, timeout=None):
            if 'login.microsoftonline.com' in req.full_url:
                if outer.entra_error:
                    raise outer.entra_error
                return _Resp(outer.entra)
            outer.hook_requests.append(json.loads(req.data.decode()))
            return _Resp(outer.hook_result)
        mint.urllib.request.urlopen = urlopen

    def tearDown(self):
        (mint.web_identity.is_enabled, mint.web_identity.mint_web_identity_token,
         mint.dynamodb, mint.urllib.request.urlopen, mint.get_federated_token) = self._saved
        mint.CONFIG = None

    def _req(self, expired=True, return_to='/orders'):
        exp = int(time.time()) - 60 if expired else int(time.time()) + 600
        cookie = _make_session_cookie({
            'sub': 'u1', 'preferred_username': 'u1@x', 'exp': exp,
            'jti': 'sess_old', 'scope': 'brand:acme',
        })
        return _request(uri='/oauth2/refresh', querystring=f'return_to={return_to}',
                        cookies={'__Secure-auth_session': cookie})

    def test_expired_session_is_renewed_with_both_cookies(self):
        resp = mint.handle_refresh(self._req())
        self.assertEqual(resp['status'], '302')
        self.assertEqual(resp['headers']['location'][0]['value'], '/orders')
        cookies = [h['value'] for h in resp['headers']['set-cookie']]
        self.assertTrue(any('__Secure-web_identity=wi.token.value' in c for c in cookies))
        auth = next(c for c in cookies if '__Secure-auth_session=' in c)
        payload = _payload_of(auth, '__Secure-auth_session')
        self.assertGreater(payload['exp'], time.time())
        self.assertNotEqual(payload['jti'], 'sess_old')

    def test_resolver_is_asked_again_for_the_sessions_scope(self):
        mint.handle_refresh(self._req())
        self.assertEqual(self.hook_requests[0]['requested_scope'], 'brand:acme')

    def test_refresh_token_rotated_to_new_jti(self):
        resp = mint.handle_refresh(self._req())
        puts = [c[1] for c in self.calls if c[0] == 'put' and c[1]['Item']['pk']['S'].startswith('REFRESH#')]
        self.assertEqual(len(puts), 1)
        self.assertEqual(puts[0]['Item']['refresh_token']['S'], 'new-refresh')
        self.assertNotEqual(puts[0]['Item']['pk']['S'], 'REFRESH#sess_old')
        deletes = [c[1] for c in self.calls if c[0] == 'delete']
        self.assertEqual(deletes[0]['Key']['pk']['S'], 'REFRESH#sess_old')
        self.assertEqual(resp['status'], '302')

    def test_cookie_outlives_the_jwt_when_refresh_enabled(self):
        resp = mint.handle_refresh(self._req())
        auth = next(h['value'] for h in resp['headers']['set-cookie'] if '__Secure-auth_session=' in h['value'])
        expires = auth.split('Expires=', 1)[1].split(';', 1)[0]
        cookie_exp = time.mktime(time.strptime(expires, '%a, %d %b %Y %H:%M:%S GMT')) - time.timezone
        self.assertGreater(cookie_exp, time.time() + 7 * 24 * 3600)

    def test_no_stored_refresh_token_goes_to_login_and_clears_cookies(self):
        self.stored = {}
        resp = mint.handle_refresh(self._req())
        self.assertEqual(resp['status'], '302')
        cookies = [h['value'] for h in resp['headers']['set-cookie']]
        self.assertTrue(all('Max-Age=0' in c for c in cookies))
        self.assertEqual(len(cookies), 2)

    def test_entra_refusal_goes_to_login_not_a_loop(self):
        self.entra_error = urllib.error.HTTPError('u', 400, 'bad', {}, None)
        resp = mint.handle_refresh(self._req())
        self.assertEqual(resp['status'], '302')
        self.assertTrue(all('Max-Age=0' in h['value'] for h in resp['headers']['set-cookie']))

    def test_scope_no_longer_held_goes_to_login(self):
        self.hook_result = {'additional_claims': {}, 'principal_tags': {}}
        resp = mint.handle_refresh(self._req())
        self.assertEqual(resp['status'], '302')
        self.assertTrue(all('Max-Age=0' in h['value'] for h in resp['headers']['set-cookie']))

    def test_bad_signature_goes_to_login(self):
        req = self._req()
        token = req['headers']['cookie'][0]['value']
        req['headers']['cookie'][0]['value'] = token[:-4] + 'AAAA'
        resp = mint.handle_refresh(req)
        self.assertEqual(resp['status'], '302')
        self.assertFalse(any(c[0] == 'put' for c in self.calls))

    def test_open_redirect_is_blocked(self):
        resp = mint.handle_refresh(self._req(return_to='https://evil.example/x'))
        self.assertEqual(resp['headers']['location'][0]['value'], '/')

    def test_protocol_relative_redirect_is_blocked(self):
        resp = mint.handle_refresh(self._req(return_to='//evil.example/x'))
        self.assertEqual(resp['headers']['location'][0]['value'], '/')

    def test_refresh_disabled_is_404(self):
        mint.CONFIG['enable_refresh'] = 'false'
        self.assertEqual(mint.handle_refresh(self._req())['status'], '404')


class CookieExpiryTests(unittest.TestCase):
    def test_unchanged_when_refresh_off(self):
        self.assertEqual(mint._cookie_expiry_ts({}, 12345), 12345)

    def test_extended_when_refresh_on(self):
        got = mint._cookie_expiry_ts({'enable_refresh': 'true', 'refresh_cookie_ttl_secs': '1000'}, 5)
        self.assertGreaterEqual(got, int(time.time()) + 999)


if __name__ == '__main__':
    unittest.main()
