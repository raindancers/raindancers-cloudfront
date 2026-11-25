"""Unit tests for the hook relay handler.

Pure-stdlib `unittest`, matching the other lambda tests here.
Run: python3 -m unittest discover -s tests -p 'test_*.py'   (from this lambda's directory)

`boto3` and `botocore` are stubbed in `sys.modules` before the handler is imported, so no
AWS SDK is needed. STS and the hook's HTTP call are patched per test.
"""

import io
import json
import os
import sys
import types
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

HANDLER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HANDLER_DIR)

sys.modules.setdefault('boto3', types.SimpleNamespace(client=lambda *a, **k: None))
_botocore = types.ModuleType('botocore')
_botocore_config = types.ModuleType('botocore.config')
_botocore_config.Config = lambda **k: k
sys.modules.setdefault('botocore', _botocore)
sys.modules.setdefault('botocore.config', _botocore_config)

import index  # noqa: E402  (must follow the sys.modules stubs above)

IDENTITY = {'sub': 'sub-1', 'email': 'a@example.test', 'provider': 'cognito'}


class _Response:
    def __init__(self, status, payload):
        self._status = status
        self._payload = json.dumps(payload).encode('utf-8')

    def getcode(self):
        return self._status

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _sts(token='tok-1', expires_in=300):
    client = MagicMock()
    client.get_web_identity_token.return_value = {
        'WebIdentityToken': token,
        'Expiration': datetime.now(timezone.utc) + timedelta(seconds=expires_in),
    }
    return client


class HookRelayTest(unittest.TestCase):
    def setUp(self):
        os.environ.update({
            'HOOK_URL': 'http://medusa.internal:9000/hooks/identity-link',
            'HOOK_AUDIENCE': 'medusa-identity-hook',
            'STS_REGION': 'eu-west-2',
        })
        os.environ.pop('HOOK_TIMEOUT_SECONDS', None)
        index._sts = None
        index._token = None
        index._token_expires_at = 0.0

    def test_sends_the_identity_with_a_bearer_token_and_returns_status_and_body(self):
        client = _sts()
        seen = {}

        def fake_urlopen(req, timeout):
            seen['url'] = req.full_url
            seen['method'] = req.get_method()
            seen['auth'] = req.get_header('Authorization')
            seen['body'] = json.loads(req.data.decode('utf-8'))
            seen['timeout'] = timeout
            return _Response(200, {'customer_id': 'cus_1'})

        with patch.object(index, '_sts_client', return_value=client), patch('urllib.request.urlopen', fake_urlopen):
            out = index.lambda_handler(IDENTITY, None)

        self.assertEqual(out, {'status': 200, 'body': {'customer_id': 'cus_1'}})
        self.assertEqual(seen['url'], 'http://medusa.internal:9000/hooks/identity-link')
        self.assertEqual(seen['method'], 'POST')
        self.assertEqual(seen['auth'], 'Bearer tok-1')
        self.assertEqual(seen['body'], IDENTITY)
        self.assertEqual(seen['timeout'], 2.5)

    def test_asks_sts_for_the_configured_audience_with_es384_and_300_seconds(self):
        client = _sts()
        with patch.object(index, '_sts_client', return_value=client), \
                patch('urllib.request.urlopen', lambda req, timeout: _Response(200, {'customer_id': 'c'})):
            index.lambda_handler(IDENTITY, None)
        client.get_web_identity_token.assert_called_once_with(
            Audience=['medusa-identity-hook'], SigningAlgorithm='ES384', DurationSeconds=300
        )

    def test_a_warm_instance_makes_one_sts_call_for_many_logins(self):
        client = _sts(expires_in=300)
        with patch.object(index, '_sts_client', return_value=client), \
                patch('urllib.request.urlopen', lambda req, timeout: _Response(200, {'customer_id': 'c'})):
            for _ in range(5):
                index.lambda_handler(IDENTITY, None)
        self.assertEqual(client.get_web_identity_token.call_count, 1)

    def test_a_token_with_less_than_the_margin_left_is_replaced(self):
        client = _sts(expires_in=300)
        with patch.object(index, '_sts_client', return_value=client), \
                patch('urllib.request.urlopen', lambda req, timeout: _Response(200, {'customer_id': 'c'})):
            index.lambda_handler(IDENTITY, None)
            index._token_expires_at = index.time.time() + 30  # under the 60 second margin
            index.lambda_handler(IDENTITY, None)
        self.assertEqual(client.get_web_identity_token.call_count, 2)

    def test_passes_a_non_2xx_answer_and_its_body_through(self):
        def conflict(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 409, 'conflict', {}, io.BytesIO(json.dumps({'type': 'conflict'}).encode()))

        with patch.object(index, '_sts_client', return_value=_sts()), patch('urllib.request.urlopen', conflict):
            out = index.lambda_handler(IDENTITY, None)
        self.assertEqual(out, {'status': 409, 'body': {'type': 'conflict'}})

    def test_an_unparseable_error_body_becomes_an_empty_object(self):
        def broken(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 502, 'bad gateway', {}, io.BytesIO(b'<html>'))

        with patch.object(index, '_sts_client', return_value=_sts()), patch('urllib.request.urlopen', broken):
            out = index.lambda_handler(IDENTITY, None)
        self.assertEqual(out, {'status': 502, 'body': {}})

    def test_a_network_error_answers_503_and_logs_no_identity_or_token(self):
        def refused(req, timeout):
            raise OSError('connection refused for a@example.test')

        with patch.object(index, '_sts_client', return_value=_sts('secret-token')), \
                patch('urllib.request.urlopen', refused), self.assertLogs(index.logger, level='ERROR') as logs:
            out = index.lambda_handler(IDENTITY, None)
        self.assertEqual(out, {'status': 503, 'body': {'type': 'unavailable'}})
        text = '\n'.join(logs.output)
        self.assertIn('OSError', text)
        self.assertNotIn('a@example.test', text)
        self.assertNotIn('secret-token', text)

    def test_an_sts_failure_answers_503_without_calling_the_hook(self):
        client = MagicMock()
        client.get_web_identity_token.side_effect = RuntimeError('OutboundWebIdentityFederationDisabled')
        called = []
        with patch.object(index, '_sts_client', return_value=client), \
                patch('urllib.request.urlopen', lambda req, timeout: called.append(1)):
            out = index.lambda_handler(IDENTITY, None)
        self.assertEqual(out['status'], 503)
        self.assertEqual(called, [])

    def test_an_old_boto3_says_so_and_answers_503(self):
        client = types.SimpleNamespace()  # no get_web_identity_token
        with patch.object(index, '_sts_client', return_value=client), self.assertLogs(index.logger, level='ERROR'):
            out = index.lambda_handler(IDENTITY, None)
        self.assertEqual(out['status'], 503)

    def test_the_timeout_comes_from_the_environment(self):
        os.environ['HOOK_TIMEOUT_SECONDS'] = '1.5'
        seen = {}

        def fake_urlopen(req, timeout):
            seen['timeout'] = timeout
            return _Response(200, {'customer_id': 'c'})

        with patch.object(index, '_sts_client', return_value=_sts()), patch('urllib.request.urlopen', fake_urlopen):
            index.lambda_handler(IDENTITY, None)
        self.assertEqual(seen['timeout'], 1.5)

    def test_the_sts_client_uses_the_regional_endpoint(self):
        made = {}

        def fake_client(name, **kwargs):
            made['name'] = name
            made.update(kwargs)
            return object()

        with patch.object(index.boto3, 'client', fake_client):
            index._sts_client()
        self.assertEqual(made['name'], 'sts')
        self.assertEqual(made['region_name'], 'eu-west-2')
        self.assertEqual(made['endpoint_url'], 'https://sts.eu-west-2.amazonaws.com')


if __name__ == '__main__':
    unittest.main()
