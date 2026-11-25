"""Unit tests for calling the identity-linking hook through the hook relay Lambda.

Pure-stdlib `unittest`, matching test_scope_resolver.py. Run from this lambda's directory:
    python3 -m unittest discover -s tests -p 'test_*.py'

With `post_auth_hook_relay_arn` set, the session Lambda invokes the relay with
`lambda:Invoke` and never calls the hook URL or reads the hook secret. With it unset,
nothing changes: the URL path with the Bearer secret is used as before.
"""

import base64
import io
import json
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

HANDLER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HANDLER_DIR)

sys.modules.setdefault('boto3', types.SimpleNamespace(client=lambda *a, **k: None))
sys.modules.setdefault('rsa', types.ModuleType('rsa'))
_botocore = types.ModuleType('botocore')
_botocore_config = types.ModuleType('botocore.config')
_botocore_config.Config = lambda **k: k
sys.modules.setdefault('botocore', _botocore)
sys.modules.setdefault('botocore.config', _botocore_config)

_BASE_CONFIG = {
    'cognito_client_id': 'client-123',
    'cognito_user_pool_id': 'pool-123',
    'cognito_region': 'us-east-1',
    'dynamodb_table_name': '',
    'dynamodb_region': 'us-east-1',
    'post_auth_hook_url': '',
    'allowed_domains': json.dumps(['example.test']),
    'session_ttl_seconds': '3600',
    'refresh_ttl_days': '30',
    'hmac_key': 'test-hmac-key',
}

_config_module = types.ModuleType('config_generated')
_config_module.get_config = lambda: dict(_BASE_CONFIG)
sys.modules['config_generated'] = _config_module

import index  # noqa: E402

RELAY_ARN = 'arn:aws:lambda:eu-west-2:123456789012:function:hook-relay:live'
IDENTITY = {'sub': 'user-1', 'email': 'a@example.test', 'provider': 'cognito'}
_VALID_CLAIMS = {'sub': 'user-1', 'email': 'a@example.test', 'iss': 'issuer'}


def _relay_config(**overrides):
    cfg = dict(_BASE_CONFIG)
    cfg.update({
        'post_auth_hook_relay_arn': RELAY_ARN,
        'post_auth_hook_relay_region': 'eu-west-2',
        'post_auth_hook_relay_timeout': '3',
    })
    cfg.update(overrides)
    return cfg


def _reset(config):
    index.CONFIG = config
    index.HMAC_SECRET = config.get('hmac_key')
    index.HOOK_SECRET = ''
    index.SCOPE_SECRET = ''
    index.RELAY_CLIENT = None
    index.dynamodb = None
    index.secretsmanager = None


def _event():
    body = base64.b64encode(json.dumps({'id_token': 'x', 'return_to': '/'}).encode()).decode()
    return {'Records': [{'cf': {'request': {'method': 'POST', 'body': {'encoding': 'base64', 'data': body}}}}]}


def _invoke_result(reply, function_error=None):
    out = {'Payload': io.BytesIO(json.dumps(reply).encode('utf-8'))}
    if function_error:
        out['FunctionError'] = function_error
    return out


class CallHookRelayTest(unittest.TestCase):
    def setUp(self):
        _reset(_relay_config())

    def test_invokes_the_relay_arn_with_the_identity_and_returns_status_and_body(self):
        client = MagicMock()
        client.invoke.return_value = _invoke_result({'status': 200, 'body': {'customer_id': 'cus_1'}})
        with patch.object(index, 'get_relay_client', return_value=client):
            status, body = index.call_identity_hook('', IDENTITY)
        self.assertEqual((status, body), (200, {'customer_id': 'cus_1'}))
        kwargs = client.invoke.call_args.kwargs
        self.assertEqual(kwargs['FunctionName'], RELAY_ARN)
        self.assertEqual(kwargs['InvocationType'], 'RequestResponse')
        self.assertEqual(json.loads(kwargs['Payload']), IDENTITY)

    def test_passes_a_non_2xx_status_through(self):
        client = MagicMock()
        client.invoke.return_value = _invoke_result({'status': 409, 'body': {'type': 'conflict'}})
        with patch.object(index, 'get_relay_client', return_value=client):
            self.assertEqual(index.call_identity_hook('', IDENTITY), (409, {'type': 'conflict'}))

    def test_a_function_error_is_a_503(self):
        client = MagicMock()
        client.invoke.return_value = _invoke_result({'errorMessage': 'boom'}, function_error='Unhandled')
        with patch.object(index, 'get_relay_client', return_value=client), self.assertLogs(index.logger, level='ERROR'):
            self.assertEqual(index.call_identity_hook('', IDENTITY), (503, {}))

    def test_a_timeout_or_transport_error_is_a_503_and_logs_only_the_error_type(self):
        client = MagicMock()
        client.invoke.side_effect = TimeoutError('read timed out for a@example.test')
        with patch.object(index, 'get_relay_client', return_value=client), self.assertLogs(index.logger, level='ERROR') as logs:
            self.assertEqual(index.call_identity_hook('', IDENTITY), (503, {}))
        text = '\n'.join(logs.output)
        self.assertIn('TimeoutError', text)
        self.assertNotIn('a@example.test', text)

    def test_a_reply_without_a_status_is_a_503(self):
        client = MagicMock()
        client.invoke.return_value = _invoke_result({'body': {}})
        with patch.object(index, 'get_relay_client', return_value=client), self.assertLogs(index.logger, level='ERROR'):
            self.assertEqual(index.call_identity_hook('', IDENTITY), (503, {}))

    def test_never_calls_the_hook_url_or_reads_the_hook_secret(self):
        client = MagicMock()
        client.invoke.return_value = _invoke_result({'status': 200, 'body': {'customer_id': 'c'}})
        with patch.object(index, 'get_relay_client', return_value=client), \
                patch('urllib.request.urlopen') as urlopen, \
                patch.object(index, 'get_hook_secret') as secret:
            index.call_identity_hook('https://api.example.test/hooks/identity-link', IDENTITY)
        urlopen.assert_not_called()
        secret.assert_not_called()

    def test_the_relay_client_is_made_in_the_relay_region_with_one_attempt(self):
        made = {}

        def fake_client(name, **kwargs):
            made['name'] = name
            made.update(kwargs)
            return object()

        with patch.object(index.boto3, 'client', fake_client):
            index.get_relay_client(index.CONFIG)
        self.assertEqual(made['name'], 'lambda')
        self.assertEqual(made['region_name'], 'eu-west-2')
        self.assertEqual(made['config']['retries'], {'max_attempts': 1})
        self.assertEqual(made['config']['read_timeout'], 3)


class HandlerWithRelayTest(unittest.TestCase):
    def test_the_handler_issues_a_session_through_the_relay_without_a_hook_url(self):
        _reset(_relay_config())
        client = MagicMock()
        client.invoke.return_value = _invoke_result({'status': 200, 'body': {'customer_id': 'cus_9'}})
        with patch.object(index, 'validate_id_token', return_value=dict(_VALID_CLAIMS)), \
                patch.object(index, 'get_relay_client', return_value=client):
            out = index.lambda_handler(_event(), None)
        self.assertEqual(out['status'], '200')
        client.invoke.assert_called_once()

    def test_a_failed_relay_issues_no_session(self):
        _reset(_relay_config())
        client = MagicMock()
        client.invoke.side_effect = OSError('down')
        with patch.object(index, 'validate_id_token', return_value=dict(_VALID_CLAIMS)), \
                patch.object(index, 'get_relay_client', return_value=client), self.assertLogs(index.logger, level='ERROR'):
            out = index.lambda_handler(_event(), None)
        self.assertEqual(out['status'], '503')
        self.assertNotIn('set-cookie', {k.lower() for k in out.get('headers', {})})

    def test_a_409_from_the_relay_issues_no_session(self):
        _reset(_relay_config())
        client = MagicMock()
        client.invoke.return_value = _invoke_result({'status': 409, 'body': {'type': 'conflict'}})
        with patch.object(index, 'validate_id_token', return_value=dict(_VALID_CLAIMS)), \
                patch.object(index, 'get_relay_client', return_value=client):
            out = index.lambda_handler(_event(), None)
        self.assertEqual(out['status'], '409')


class UrlPathUnchangedTest(unittest.TestCase):
    def test_without_a_relay_the_url_and_bearer_secret_are_used_as_before(self):
        _reset(dict(_BASE_CONFIG, post_auth_hook_url='https://api.example.test/hooks/identity-link'))
        index.HOOK_SECRET = 'shared-secret'
        seen = {}

        class _Resp:
            def getcode(self):
                return 200

            def read(self):
                return json.dumps({'customer_id': 'cus_1'}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout):
            seen['url'] = req.full_url
            seen['auth'] = req.get_header('Authorization')
            seen['timeout'] = timeout
            return _Resp()

        with patch('urllib.request.urlopen', fake_urlopen), patch.object(index, 'get_relay_client') as relay:
            result = index.call_identity_hook('https://api.example.test/hooks/identity-link', IDENTITY)
        self.assertEqual(result, (200, {'customer_id': 'cus_1'}))
        self.assertEqual(seen, {'url': 'https://api.example.test/hooks/identity-link', 'auth': 'Bearer shared-secret', 'timeout': 3})
        relay.assert_not_called()


if __name__ == '__main__':
    unittest.main()
