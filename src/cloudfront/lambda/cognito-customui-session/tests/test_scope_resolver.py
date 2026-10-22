"""Unit tests for the Scope Resolver merge in the session-mint Lambda.

Pure-stdlib `unittest` (no pytest/moto), matching scim-provisioning/tests.
Run: python3 -m unittest discover -s tests -p 'test_*.py'

The handler imports `boto3`, `rsa`, and `config_generated` at module scope.
None of those are needed to exercise the resolver merge, so we stub them in
`sys.modules` BEFORE importing the handler, then drive it with a minimal
Lambda@Edge POST event. `validate_id_token` is patched per-test so a real RS256
token is unnecessary; the resolver HTTP call and Secrets Manager are patched too.
"""

import base64
import json
import os
import sys
import types
import unittest
from unittest.mock import patch

HANDLER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HANDLER_DIR)

# --- Stub module-level imports the handler makes before we import it ----------
sys.modules.setdefault('boto3', types.SimpleNamespace(client=lambda *a, **k: None))
sys.modules.setdefault('rsa', types.ModuleType('rsa'))

_BASE_CONFIG = {
    'cognito_client_id': 'client-123',
    'cognito_user_pool_id': 'pool-123',
    'cognito_region': 'us-east-1',
    'dynamodb_table_name': '',  # skip server-side persistence in these tests
    'dynamodb_region': 'us-east-1',
    'post_auth_hook_url': '',
    'allowed_domains': json.dumps(['example.test']),
    'session_ttl_seconds': '3600',
    'refresh_ttl_days': '30',
    'hmac_key': 'test-hmac-key',
    'jwt_claims_whitelist': json.dumps([
        'sub', 'email', 'roles',
        'https://aws.amazon.com/tags/principal_tags/Claims',
    ]),
}


def _make_config(**overrides):
    cfg = dict(_BASE_CONFIG)
    cfg.update(overrides)
    return cfg


# config_generated.get_config is import-time; stub it returning the base config.
_config_module = types.ModuleType('config_generated')
_config_module.get_config = lambda: dict(_BASE_CONFIG)
sys.modules['config_generated'] = _config_module

import index  # noqa: E402  (must follow the sys.modules stubs above)


def _event():
    """Minimal Lambda@Edge origin-request POST event carrying an id_token."""
    body = base64.b64encode(json.dumps({'id_token': 'x', 'return_to': '/'}).encode()).decode()
    return {'Records': [{'cf': {'request': {
        'method': 'POST',
        'body': {'encoding': 'base64', 'data': body},
    }}}]}


_VALID_CLAIMS = {'sub': 'user-1', 'email': 'a@example.test', 'iss': 'issuer'}


def _reset_module_caches(config):
    """Point the handler's cached config/secrets at a per-test config."""
    index.CONFIG = config
    index.HMAC_SECRET = config.get('hmac_key')
    index.HOOK_SECRET = ''
    index.SCOPE_SECRET = ''
    index.dynamodb = None
    index.secretsmanager = None


def _get_set_cookie(resp):
    return resp['headers'].get('set-cookie')


def _decode_payload(resp):
    cookie = _get_set_cookie(resp)[0]['value']
    token = cookie.split('=', 1)[1].split(';', 1)[0]
    payload_b64 = token.split('.')[1]
    return json.loads(index._b64url_decode(payload_b64))


class ScopeResolverTests(unittest.TestCase):

    def _run(self, config, resolver=None, resolver_raises=None):
        _reset_module_caches(config)
        patchers = [patch.object(index, 'validate_id_token', return_value=dict(_VALID_CLAIMS))]
        if resolver_raises is not None:
            patchers.append(patch.object(index, 'call_scope_resolver', side_effect=resolver_raises))
        elif resolver is not None:
            patchers.append(patch.object(index, 'call_scope_resolver', return_value=resolver))
        for p in patchers:
            p.start()
        self.addCleanup(lambda ps=patchers: [p.stop() for p in ps])
        return index.lambda_handler(_event(), None)

    def test_mint_unchanged_without_resolver(self):
        """R1: no scope_resolver_url => no resolver call, cookie minted, no tags."""
        with patch.object(index, 'call_scope_resolver') as spy:
            resp = self._run(_make_config())
        spy.assert_not_called()
        self.assertEqual(resp['status'], '200')
        payload = _decode_payload(resp)
        self.assertNotIn('https://aws.amazon.com/tags/principal_tags/Claims', payload)

    def test_resolver_claims_and_tags_merged(self):
        """R2: whitelisted role claim appears; whitelisted scope in :k=v: tag."""
        resp = self._run(
            _make_config(scope_resolver_url='https://resolver.test/scope'),
            resolver=(200, {
                'claims': {'roles': {'brandX': {'custom': 5}}},
                'principal_tags': {'scope': 'brandX'},
            }),
        )
        self.assertEqual(resp['status'], '200')
        payload = _decode_payload(resp)
        self.assertEqual(payload['roles'], {'brandX': {'custom': 5}})
        self.assertEqual(
            payload['https://aws.amazon.com/tags/principal_tags/Claims'],
            ':scope=brandX:',
        )

    def test_non_whitelisted_dropped(self):
        """R3: non-whitelisted key dropped, whitelisted present, mint succeeds."""
        resp = self._run(
            _make_config(scope_resolver_url='https://resolver.test/scope'),
            resolver=(200, {
                'claims': {'roles': {'brandX': {'custom': 1}}, 'evil': 'nope'},
                'principal_tags': {},
            }),
        )
        self.assertEqual(resp['status'], '200')
        payload = _decode_payload(resp)
        self.assertIn('roles', payload)
        self.assertNotIn('evil', payload)

    def test_resolver_timeout_fails_closed(self):
        """R4: a timeout (raised) => 503, no Set-Cookie."""
        resp = self._run(
            _make_config(scope_resolver_url='https://resolver.test/scope'),
            resolver_raises=TimeoutError('timed out'),
        )
        self.assertEqual(resp['status'], '503')
        self.assertIsNone(_get_set_cookie(resp))

    def test_resolver_non2xx_fails_closed(self):
        """R4: a non-2xx resolver status => 503, no Set-Cookie."""
        resp = self._run(
            _make_config(scope_resolver_url='https://resolver.test/scope'),
            resolver=(500, {'error': 'boom'}),
        )
        self.assertEqual(resp['status'], '503')
        self.assertIsNone(_get_set_cookie(resp))

    def test_oversize_token_refused(self):
        """R5: an assembled token over scope_token_max_bytes => 500, no cookie."""
        resp = self._run(
            _make_config(
                scope_resolver_url='https://resolver.test/scope',
                scope_token_max_bytes='256',
            ),
            resolver=(200, {
                'claims': {'roles': {'big': 'x' * 2000}},
                'principal_tags': {},
            }),
        )
        self.assertEqual(resp['status'], '500')
        self.assertEqual(json.loads(resp['body'])['error'], 'scope_token_too_large')
        self.assertIsNone(_get_set_cookie(resp))


if __name__ == '__main__':
    unittest.main()
