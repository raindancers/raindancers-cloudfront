"""Unit tests for the RS256 web-identity half (web_identity.py).

The module calls KMS only inside its functions, so importing it is side-effect
free. These tests stub the KMS client to avoid any AWS call, and assert:
  1. is_enabled() keys off the signing-key id (feature off when absent).
  2. mint_web_identity_token() assembles a compact RS256 JWS with the right
     header/claims and carries the principal-tags brand claim verbatim.
  3. jwks_document() returns a single RSA JWK (use=sig, alg=RS256).
"""
import base64
import importlib.util
import json
import os
import sys
import types
import unittest


def _load():
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, os.pardir, 'web_identity.py')
    spec = importlib.util.spec_from_file_location('web_identity_under_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wi = _load()


def _b64url_json(segment):
    pad = '=' * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


class FakeKms:
    """Minimal KMS stub: sign returns a fixed signature; get_public_key returns
    a real small RSA DER so _public_jwk can parse it."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._der = self._priv.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def sign(self, **kwargs):
        return {'Signature': b'\x01\x02\x03\x04'}

    def get_public_key(self, **kwargs):
        return {'PublicKey': self._der}


class WebIdentityTests(unittest.TestCase):
    def setUp(self):
        # Reset module caches + inject the fake KMS.
        wi._KMS = FakeKms()
        wi._PUBLIC_KEY_CACHE.clear()

    def test_is_enabled(self):
        self.assertFalse(wi.is_enabled({}))
        self.assertFalse(wi.is_enabled({'web_identity_signing_key_id': ''}))
        self.assertTrue(wi.is_enabled({'web_identity_signing_key_id': 'key-1'}))

    def test_mint_assembles_rs256_with_brand_claim(self):
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        claim = 'https://aws.amazon.com/tags/principal_tags/Claims'
        token = wi.mint_web_identity_token(
            config, 'ap-southeast-2',
            subject='user-sub',
            principal_tags_claim=claim,
            principal_tags_value=':brand=acme:',
            ttl_exp=9999999999,
        )
        header_b64, payload_b64, sig_b64 = token.split('.')
        header = _b64url_json(header_b64)
        payload = _b64url_json(payload_b64)
        self.assertEqual(header['alg'], 'RS256')
        self.assertEqual(header['kid'], 'key-1')
        self.assertEqual(payload['iss'], 'https://admin.example.com')
        self.assertEqual(payload['aud'], 'https://admin.example.com')
        self.assertEqual(payload['sub'], 'user-sub')
        self.assertEqual(payload['exp'], 9999999999)
        self.assertEqual(payload[claim], ':brand=acme:')
        self.assertTrue(sig_b64)  # signature segment present

    def test_mint_omits_empty_brand_claim(self):
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        claim = 'https://aws.amazon.com/tags/principal_tags/Claims'
        token = wi.mint_web_identity_token(
            config, '', subject='u', principal_tags_claim=claim,
            principal_tags_value=None, ttl_exp=1,
        )
        payload = _b64url_json(token.split('.')[1])
        self.assertNotIn(claim, payload)

    def test_mint_adds_preferred_username_when_given(self):
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        # username provided -> preferred_username claim present, sub unchanged.
        token = wi.mint_web_identity_token(
            config, 'ap-southeast-2', subject='user-sub',
            principal_tags_claim=None, principal_tags_value=None,
            ttl_exp=9999999999, username='u@x.com',
        )
        payload = _b64url_json(token.split('.')[1])
        self.assertEqual(payload['preferred_username'], 'u@x.com')
        self.assertEqual(payload['sub'], 'user-sub')

    def test_mint_omits_preferred_username_when_absent(self):
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        # default (None) and empty string both omit the claim.
        token_default = wi.mint_web_identity_token(
            config, 'ap-southeast-2', subject='user-sub',
            principal_tags_claim=None, principal_tags_value=None,
            ttl_exp=9999999999,
        )
        token_empty = wi.mint_web_identity_token(
            config, 'ap-southeast-2', subject='user-sub',
            principal_tags_claim=None, principal_tags_value=None,
            ttl_exp=9999999999, username='',
        )
        self.assertNotIn('preferred_username', _b64url_json(token_default.split('.')[1]))
        self.assertNotIn('preferred_username', _b64url_json(token_empty.split('.')[1]))

    def test_jwks_document_single_rsa_jwk(self):
        config = {'web_identity_signing_key_id': 'key-1'}
        resp = wi.jwks_document(config, 'ap-southeast-2')
        self.assertEqual(resp['status'], '200')
        body = json.loads(resp['body'])
        self.assertEqual(len(body['keys']), 1)
        jwk = body['keys'][0]
        self.assertEqual(jwk['kty'], 'RSA')
        self.assertEqual(jwk['use'], 'sig')
        self.assertEqual(jwk['alg'], 'RS256')
        self.assertEqual(jwk['kid'], 'key-1')
        self.assertIn('n', jwk)
        self.assertIn('e', jwk)

    def test_openid_configuration_document(self):
        # STS AssumeRoleWithWebIdentity discovers the jwks_uri from this doc;
        # without it STS fails with InvalidIdentityTokenException.
        config = {
            'web_identity_signing_key_id': 'key-1',
            'web_identity_issuer': 'https://admin.example.com',
        }
        resp = wi.openid_configuration_document(config)
        self.assertEqual(resp['status'], '200')
        self.assertEqual(
            resp['headers']['content-type'][0]['value'], 'application/json')
        doc = json.loads(resp['body'])
        self.assertEqual(doc['issuer'], 'https://admin.example.com')
        self.assertEqual(
            doc['jwks_uri'], 'https://admin.example.com/.well-known/jwks.json')
        self.assertEqual(doc['id_token_signing_alg_values_supported'], ['RS256'])
        self.assertEqual(doc['response_types_supported'], ['id_token'])
        self.assertEqual(doc['subject_types_supported'], ['public'])

    def test_openid_configuration_trailing_slash_issuer(self):
        # A trailing slash on the issuer must not double up in jwks_uri.
        config = {
            'web_identity_signing_key_id': 'key-1',
            'web_identity_issuer': 'https://admin.example.com/',
        }
        doc = json.loads(wi.openid_configuration_document(config)['body'])
        self.assertEqual(doc['issuer'], 'https://admin.example.com')
        self.assertEqual(
            doc['jwks_uri'], 'https://admin.example.com/.well-known/jwks.json')


if __name__ == '__main__':
    unittest.main()
