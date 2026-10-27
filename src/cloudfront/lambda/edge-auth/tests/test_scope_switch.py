"""Unit tests for the scope SWITCH / re-mint route (#195 §5.7).

``handle_scope_switch`` re-mints the operator's session + web_identity cookies
for a REQUESTED scope, reusing the existing session (no Entra round-trip). It
calls config, the resolver hook, the KMS mint and DynamoDB only inside the
function, so these tests stub each collaborator and assert the dispatch logic,
the fail-closed branches, and the cookie output.

The mint module imports ``boto3``, ``jwt`` and ``config_generated`` at module
scope; ``config_generated.get_config`` reads Secrets Manager at CALL time, not
import, so importing is side-effect free once ``config_generated`` is stubbed.
The file name has a hyphen, so it is loaded by path with importlib.
"""
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import types
import unittest


def _load_mint_module():
    if 'config_generated' not in sys.modules:
        stub = types.ModuleType('config_generated')
        stub.get_config = lambda: {}
        sys.modules['config_generated'] = stub
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, os.pardir, 'oauth-callback.py')
    spec = importlib.util.spec_from_file_location('entra_oauth_callback_switch', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mint = _load_mint_module()

HMAC_SECRET = 'test-hmac-secret'


def _make_session_cookie(payload):
    """Build a valid HS256 session cookie for `payload` using HMAC_SECRET."""
    header = {'alg': 'HS256', 'typ': 'JWT'}
    hb = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
    pb = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
    sig = hmac.new(HMAC_SECRET.encode(), f'{hb}.{pb}'.encode(), hashlib.sha256).digest()
    sb = base64.urlsafe_b64encode(sig).decode().rstrip('=')
    return f'{hb}.{pb}.{sb}'


def _request(uri='/oauth2/switch', querystring='scope=brand%3Aacme', cookies=None):
    headers = {}
    if cookies:
        cookie_str = '; '.join(f'{k}={v}' for k, v in cookies.items())
        headers['cookie'] = [{'key': 'Cookie', 'value': cookie_str}]
    return {'uri': uri, 'querystring': querystring, 'headers': headers}


class HelperTests(unittest.TestCase):
    def test_parse_cookies(self):
        req = _request(cookies={'a': '1', 'b': '2'})
        self.assertEqual(mint._parse_request_cookies(req), {'a': '1', 'b': '2'})

    def test_parse_cookies_no_header(self):
        self.assertEqual(mint._parse_request_cookies({'headers': {}}), {})

    def test_requested_scope_unquotes(self):
        self.assertEqual(mint._requested_scope({'querystring': 'scope=brand%3Aacme'}), 'brand:acme')

    def test_requested_scope_estate(self):
        self.assertEqual(mint._requested_scope({'querystring': 'scope=estate'}), 'estate')

    def test_requested_scope_absent(self):
        self.assertIsNone(mint._requested_scope({'querystring': 'foo=bar'}))
        self.assertIsNone(mint._requested_scope({'querystring': ''}))

    def test_verify_session_cookie_valid(self):
        mint.HMAC_SECRET = HMAC_SECRET
        cookie = _make_session_cookie({'sub': 'u1', 'exp': 9999999999})
        cookies = {'__Host-auth_session': cookie}
        got = mint._verify_session_cookie(cookies, '__Host-')
        self.assertIsNotNone(got)
        self.assertEqual(got['sub'], 'u1')

    def test_verify_session_cookie_bad_signature(self):
        mint.HMAC_SECRET = HMAC_SECRET
        cookie = _make_session_cookie({'sub': 'u1'})
        tampered = cookie[:-4] + 'AAAA'
        got = mint._verify_session_cookie({'__Host-auth_session': tampered}, '__Host-')
        self.assertIsNone(got)

    def test_verify_session_cookie_missing(self):
        mint.HMAC_SECRET = HMAC_SECRET
        self.assertIsNone(mint._verify_session_cookie({}, '__Host-'))


class SwitchHandlerTests(unittest.TestCase):
    def setUp(self):
        mint.HMAC_SECRET = HMAC_SECRET
        mint.CONFIG = {
            'hmac_key': HMAC_SECRET,
            'web_identity_signing_key_id': 'key-123',
            'post_auth_hook_url': 'https://resolver.example/invoke',
            'jwt_claims_whitelist': json.dumps([
                'sub', 'exp', 'iss', 'idp', 'preferred_username',
                'ui_permissions', 'scope', 'scopes',
                mint.PRINCIPAL_TAGS_CLAIM,
            ]),
            'cookie_domain': 'admin.example.com',
            'dynamodb_table_name': 'sessions',
        }
        self._wi_enabled = mint.web_identity.is_enabled
        self._wi_mint = mint.web_identity.mint_web_identity_token
        mint.web_identity.is_enabled = lambda cfg: bool(cfg.get('web_identity_signing_key_id'))
        mint.web_identity.mint_web_identity_token = lambda *a, **k: 'wi.token.value'
        self._dynamo = mint.dynamodb
        self.calls = []
        mint.dynamodb = types.SimpleNamespace(
            update_item=lambda **kw: self.calls.append(('update', kw)),
            put_item=lambda **kw: self.calls.append(('put', kw)),
        )
        self._urlopen = mint.urllib.request.urlopen
        self._hook_result = {
            'additional_claims': {'ui_permissions': ['subject.read'], 'scope': 'brand:acme'},
            'principal_tags': {'brand': 'acme', 'subject.read': '1'},
        }

        class _Resp:
            def __init__(self, body):
                self._b = json.dumps(body).encode()
            def read(self):
                return self._b
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        outer = self
        mint.urllib.request.urlopen = lambda req, timeout=None: _Resp(outer._hook_result)

    def tearDown(self):
        mint.web_identity.is_enabled = self._wi_enabled
        mint.web_identity.mint_web_identity_token = self._wi_mint
        mint.dynamodb = self._dynamo
        mint.urllib.request.urlopen = self._urlopen
        mint.CONFIG = None

    def _authed_request(self, scope='scope=brand%3Aacme'):
        cookie = _make_session_cookie({'sub': 'u1', 'preferred_username': 'u1@x', 'exp': 9999999999, 'jti': 'sess_old'})
        return _request(querystring=scope, cookies={'__Secure-auth_session': cookie})

    def test_happy_path_remints_and_sets_cookies(self):
        resp = mint.handle_scope_switch(self._authed_request())
        self.assertEqual(resp['status'], '200')
        body = json.loads(resp['body'])
        self.assertEqual(body['scope'], 'brand:acme')
        self.assertTrue(body['jti'].startswith('sess_'))
        self.assertNotEqual(body['jti'], 'sess_old')
        cookies = [h['value'] for h in resp['headers']['set-cookie']]
        self.assertTrue(any('__Secure-auth_session=' in c for c in cookies))
        self.assertTrue(any('__Secure-web_identity=wi.token.value' in c for c in cookies))

    def test_old_jti_revoked_and_new_session_stored(self):
        mint.handle_scope_switch(self._authed_request())
        kinds = [c[0] for c in self.calls]
        self.assertIn('update', kinds)
        self.assertIn('put', kinds)

    def test_missing_session_is_401(self):
        req = _request(cookies={})
        resp = mint.handle_scope_switch(req)
        self.assertEqual(resp['status'], '401')
        self.assertEqual(json.loads(resp['body'])['error'], 'invalid_session')

    def test_missing_scope_is_400(self):
        cookie = _make_session_cookie({'sub': 'u1', 'exp': 9999999999})
        req = _request(querystring='', cookies={'__Secure-auth_session': cookie})
        resp = mint.handle_scope_switch(req)
        self.assertEqual(resp['status'], '400')
        self.assertEqual(json.loads(resp['body'])['error'], 'missing_scope')

    def test_scope_not_held_is_403(self):
        self._hook_result = {'additional_claims': {'ui_permissions': [], 'scopes': []}, 'principal_tags': {}}
        resp = mint.handle_scope_switch(self._authed_request())
        self.assertEqual(resp['status'], '403')
        self.assertEqual(json.loads(resp['body'])['error'], 'scope_not_held')

    def test_feature_off_is_404(self):
        mint.CONFIG = {'hmac_key': HMAC_SECRET}
        resp = mint.handle_scope_switch(self._authed_request())
        self.assertEqual(resp['status'], '404')

    def test_new_token_carries_new_scope_tags(self):
        resp = mint.handle_scope_switch(self._authed_request())
        auth = next(h['value'] for h in resp['headers']['set-cookie']
                    if '__Secure-auth_session=' in h['value'])
        token = auth.split('__Secure-auth_session=', 1)[1].split(';', 1)[0]
        payload_b64 = token.split('.')[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=' * (-len(payload_b64) % 4)))
        self.assertEqual(payload[mint.PRINCIPAL_TAGS_CLAIM], ':brand=acme:subject.read=1:')
        self.assertEqual(payload['scope'], 'brand:acme')


if __name__ == '__main__':
    unittest.main()
