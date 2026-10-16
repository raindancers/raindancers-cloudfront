"""
Handler test suite for the SCIM provisioning service.

Pure-stdlib `unittest` (no pytest/moto dependency, matching this environment):
  * An in-memory fake DynamoDB table stubs the `store` module's boto3 resource.
  * A local RSA key stubs KMS sign/get_public_key, so JWT mint + verify round-trip
    for real (RS256) without AWS.
  * Secrets Manager is stubbed to return a known client secret.

Run: python3 -m unittest discover -s tests -p 'test_*.py'
"""

import base64
import importlib
import json
import os
import sys
import time
import unittest
import uuid
from unittest.mock import MagicMock, patch

HANDLER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HANDLER_DIR)

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# --- A local RSA key standing in for the KMS asymmetric signing key -----------
_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUB_DER = _RSA.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

CLIENT_SECRET = 'super-secret-client-value'
ISSUER = 'https://scim.example.test'


class FakeTable:
    """Minimal in-memory DynamoDB table supporting the store module's calls."""
    def __init__(self):
        self.items = {}   # (pk, sk) -> item

    def put_item(self, Item):
        self.items[(Item['pk'], Item['sk'])] = dict(Item)

    def get_item(self, Key):
        it = self.items.get((Key['pk'], Key['sk']))
        return {'Item': dict(it)} if it else {}

    def delete_item(self, Key):
        self.items.pop((Key['pk'], Key['sk']), None)

    def query(self, IndexName, KeyConditionExpression, Limit=None):
        # KeyConditionExpression is a boto3 Key().eq() condition; pull its value.
        target = KeyConditionExpression._values[1]
        attr = {'GSI1': 'gsi1pk', 'GSI2': 'gsi2pk'}[IndexName]
        hits = [dict(v) for v in self.items.values() if v.get(attr) == target]
        return {'Items': hits[:Limit] if Limit else hits}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, **kw):
        it = self.items[(Key['pk'], Key['sk'])]
        vals = ExpressionAttributeValues
        if UpdateExpression.startswith('SET active'):
            it['active'] = vals[':a']
            it['updatedAt'] = vals[':u']
        elif UpdateExpression.startswith('SET displayName'):
            it['displayName'] = vals[':d']
            it['updatedAt'] = vals[':u']
        elif UpdateExpression.startswith('ADD groupIds'):
            it.setdefault('groupIds', set()).update(vals[':g'])
            it['updatedAt'] = vals[':u']
        elif UpdateExpression.startswith('DELETE groupIds'):
            it.get('groupIds', set()).difference_update(vals[':g'])
            it['updatedAt'] = vals[':u']


def fake_kms():
    kms = MagicMock()
    def _sign(KeyId, Message, MessageType, SigningAlgorithm):
        sig = _RSA.sign(Message, padding.PKCS1v15(), hashes.SHA256())
        return {'Signature': sig}
    kms.sign.side_effect = _sign
    kms.get_public_key.return_value = {'PublicKey': _PUB_DER}
    return kms


def fake_secrets(secret=CLIENT_SECRET):
    sm = MagicMock()
    sm.get_secret_value.return_value = {'SecretString': secret}
    return sm


class HandlerTestBase(unittest.TestCase):
    def setUp(self):
        os.environ.update({
            'AUTH_MODE': 'OAUTH_CLIENT_CREDENTIALS',
            'SCIM_BASE_PATH': '/scim/v2',
            'TOKEN_ENDPOINT_PATH': '/oauth2/token',
            'JWKS_PATH': '/.well-known/jwks.json',
            'TABLE_NAME': 'test-table',
            'SIGNING_KEY_ID': 'test-key-id',
            'TOKEN_ISSUER': ISSUER,
            'ACCESS_TOKEN_TTL': '3600',
            'CLIENT_SECRET_ARN': 'arn:secret:client',
            'STATIC_BEARER_ARN': 'arn:secret:bearer',
        })
        self.table = FakeTable()
        self.kms = fake_kms()
        self.sm = fake_secrets()

        # Fresh module imports with boto3 patched.
        for m in ('index', 'auth', 'scim', 'store', 'tokens'):
            sys.modules.pop(m, None)
        import store, tokens, auth, scim, index
        self.store, self.tokens, self.auth, self.scim, self.index = store, tokens, auth, scim, index

        # Patch boto3 usage.
        self._p_res = patch.object(store.boto3, 'resource', return_value=MagicMock(Table=lambda n: self.table))
        self._p_res.start()
        tokens._KMS = self.kms
        self._p_cli = patch.object(tokens.boto3, 'client', side_effect=self._client)
        self._p_cli.start()
        self._p_auth_cli = patch.object(auth.boto3, 'client', side_effect=self._client)
        self._p_auth_cli.start()
        tokens._PUBLIC_KEY_CACHE.clear()

    def tearDown(self):
        self._p_res.stop(); self._p_cli.stop(); self._p_auth_cli.stop()

    def _client(self, name, *a, **k):
        if name == 'kms':
            return self.kms
        if name == 'secretsmanager':
            return self.sm
        return MagicMock()

    # -- event helpers --
    def _event(self, method, path, body=None, headers=None, query=None, b64=False):
        b = body
        if body is not None and not isinstance(body, str):
            b = json.dumps(body)
        return {
            'requestContext': {'http': {'method': method, 'path': path}},
            'headers': headers or {},
            'body': b,
            'isBase64Encoded': b64,
            'queryStringParameters': query,
        }

    def _bearer(self, token):
        return {'authorization': f'Bearer {token}'}

    def _mint(self, sub='client-1'):
        tok, _ = self.tokens.mint_access_token(sub)
        return tok


class TestTokenEndpoint(HandlerTestBase):
    def _token_event(self, basic=None, body_creds=None):
        headers = {}
        if basic:
            raw = base64.b64encode(f'{basic[0]}:{basic[1]}'.encode()).decode()
            headers['authorization'] = f'Basic {raw}'
        form = 'grant_type=client_credentials'
        if body_creds:
            form += f'&client_id={body_creds[0]}&client_secret={body_creds[1]}'
        return {'requestContext': {'http': {'method': 'POST', 'path': '/oauth2/token'}},
                'headers': headers, 'body': form, 'isBase64Encoded': False}

    def test_body_credentials_happy_path(self):
        resp = self.index.handler(self._token_event(body_creds=('c1', CLIENT_SECRET)), None)
        self.assertEqual(resp['statusCode'], 200)
        self.assertEqual(json.loads(resp['body'])['token_type'], 'Bearer')

    def test_basic_header_happy_path(self):
        resp = self.index.handler(self._token_event(basic=('c1', CLIENT_SECRET)), None)
        self.assertEqual(resp['statusCode'], 200)

    def test_entra_dual_credentials_accepted(self):
        # Entra sends creds in BOTH the Basic header AND the body, identically.
        resp = self.index.handler(
            self._token_event(basic=('c1', CLIENT_SECRET), body_creds=('c1', CLIENT_SECRET)), None)
        self.assertEqual(resp['statusCode'], 200, resp['body'])

    def test_conflicting_dual_credentials_rejected(self):
        resp = self.index.handler(
            self._token_event(basic=('c1', CLIENT_SECRET), body_creds=('c1', 'WRONG')), None)
        self.assertEqual(resp['statusCode'], 401)
        self.assertEqual(json.loads(resp['body'])['error'], 'invalid_client')

    def test_bad_secret_rejected(self):
        resp = self.index.handler(self._token_event(body_creds=('c1', 'nope')), None)
        self.assertEqual(resp['statusCode'], 401)

    def test_wrong_grant_rejected(self):
        ev = {'requestContext': {'http': {'method': 'POST', 'path': '/oauth2/token'}},
              'headers': {}, 'body': 'grant_type=authorization_code', 'isBase64Encoded': False}
        resp = self.index.handler(ev, None)
        self.assertEqual(resp['statusCode'], 400)
        self.assertEqual(json.loads(resp['body'])['error'], 'unsupported_grant_type')


class TestJwksAndVerify(HandlerTestBase):
    def test_jwks_round_trip(self):
        jwks = json.loads(self.index.handler(self._event('GET', '/.well-known/jwks.json'), None)['body'])
        self.assertEqual(jwks['keys'][0]['kty'], 'RSA')
        token = self._mint('client-1')
        self.assertIsNotNone(self.tokens.verify_access_token(token))

    def test_tampered_token_fails(self):
        token = self._mint('client-1')
        tampered = token[:-4] + 'AAAA'
        self.assertIsNone(self.tokens.verify_access_token(tampered))


class TestAuthFailClosed(HandlerTestBase):
    def test_scim_without_token_401(self):
        resp = self.index.handler(self._event('GET', '/scim/v2/Users', query={'filter': 'userName eq "a"'}), None)
        self.assertEqual(resp['statusCode'], 401)

    def test_scim_with_valid_token_passes(self):
        resp = self.index.handler(
            self._event('GET', '/scim/v2/Users', headers=self._bearer(self._mint()),
                        query={'filter': 'userName eq "nobody"'}), None)
        self.assertEqual(resp['statusCode'], 200)

    def test_expired_token_denied(self):
        os.environ['ACCESS_TOKEN_TTL'] = '-10'  # already expired
        token = self._mint()
        os.environ['ACCESS_TOKEN_TTL'] = '3600'
        resp = self.index.handler(
            self._event('GET', '/scim/v2/Users', headers=self._bearer(token),
                        query={'filter': 'userName eq "a"'}), None)
        self.assertEqual(resp['statusCode'], 401)


class TestScimLifecycle(HandlerTestBase):
    def _auth(self):
        return self._bearer(self._mint())

    def test_create_get_delete_user(self):
        create = self.index.handler(self._event(
            'POST', '/scim/v2/Users', headers=self._auth(),
            body={'externalId': 'ext-1', 'userName': 'a@x.io', 'active': True}), None)
        self.assertEqual(create['statusCode'], 201)
        scim_id = json.loads(create['body'])['id']

        got = self.index.handler(self._event('GET', f'/scim/v2/Users/{scim_id}', headers=self._auth()), None)
        self.assertEqual(got['statusCode'], 200)

        deleted = self.index.handler(self._event('DELETE', f'/scim/v2/Users/{scim_id}', headers=self._auth()), None)
        self.assertEqual(deleted['statusCode'], 204)

        gone = self.index.handler(self._event('GET', f'/scim/v2/Users/{scim_id}', headers=self._auth()), None)
        self.assertEqual(gone['statusCode'], 404)

    def test_filter_match_before_create(self):
        self.index.handler(self._event(
            'POST', '/scim/v2/Users', headers=self._auth(),
            body={'externalId': 'ext-2', 'userName': 'bob@x.io'}), None)
        hit = self.index.handler(self._event(
            'GET', '/scim/v2/Users', headers=self._auth(),
            query={'filter': 'userName eq "bob@x.io"'}), None)
        self.assertEqual(json.loads(hit['body'])['totalResults'], 1)
        miss = self.index.handler(self._event(
            'GET', '/scim/v2/Users', headers=self._auth(),
            query={'filter': 'externalId eq "nope"'}), None)
        self.assertEqual(json.loads(miss['body'])['totalResults'], 0)

    def test_unsupported_filter_400(self):
        resp = self.index.handler(self._event(
            'GET', '/scim/v2/Users', headers=self._auth(),
            query={'filter': 'userName sw "a"'}), None)
        self.assertEqual(resp['statusCode'], 400)

    def test_deactivate_via_patch(self):
        create = self.index.handler(self._event(
            'POST', '/scim/v2/Users', headers=self._auth(),
            body={'externalId': 'ext-3', 'userName': 'c@x.io', 'active': True}), None)
        scim_id = json.loads(create['body'])['id']
        patched = self.index.handler(self._event(
            'PATCH', f'/scim/v2/Users/{scim_id}', headers=self._auth(),
            body={'schemas': [self.scim.PATCHOP_SCHEMA],
                  'Operations': [{'op': 'replace', 'path': 'active', 'value': False}]}), None)
        self.assertEqual(patched['statusCode'], 200)
        self.assertFalse(json.loads(patched['body'])['active'])

    def test_group_membership_fanout(self):
        u = self.index.handler(self._event(
            'POST', '/scim/v2/Users', headers=self._auth(),
            body={'externalId': 'ext-4', 'userName': 'd@x.io'}), None)
        scim_id = json.loads(u['body'])['id']
        self.index.handler(self._event(
            'POST', '/scim/v2/Groups', headers=self._auth(),
            body={'externalId': 'grp-1', 'displayName': 'Ops'}), None)
        self.index.handler(self._event(
            'PATCH', '/scim/v2/Groups/grp-1', headers=self._auth(),
            body={'Operations': [{'op': 'add', 'path': 'members', 'value': [{'value': scim_id}]}]}), None)
        # The group id now appears on the user's denormalised item.
        item = self.store.get_user_by_scim_id(scim_id)
        self.assertIn('grp-1', item.get('groupIds', set()))
        # consumer hot-path read shape
        hot = self.store.get_user_by_external_id('ext-4')
        self.assertIn('grp-1', hot.get('groupIds', set()))

    def test_discovery_documents(self):
        for route in ('/scim/v2/ServiceProviderConfig', '/scim/v2/Schemas', '/scim/v2/ResourceTypes'):
            r = self.index.handler(self._event('GET', route, headers=self._auth()), None)
            self.assertEqual(r['statusCode'], 200, route)
        spc = json.loads(self.index.handler(
            self._event('GET', '/scim/v2/ServiceProviderConfig', headers=self._auth()), None)['body'])
        self.assertTrue(spc['patch']['supported'])
        self.assertEqual(spc['authenticationSchemes'][0]['type'], 'oauthbearertoken')


if __name__ == '__main__':
    unittest.main()
