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

    def test_mint_principal_tags_map_emits_aws_tags_object(self):
        # The STS-correct session-tags claim: a raw tag map becomes
        # https://aws.amazon.com/tags -> {principal_tags: {k: [v]}}, which STS
        # parses into per-key aws:PrincipalTag/<k>. This is what makes the
        # brand/permission policy fence work (the colon-string did NOT —
        # STS stored it as a single tag named "Claims").
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        token = wi.mint_web_identity_token(
            config, 'ap-southeast-2', subject='user-sub',
            principal_tags_claim='https://aws.amazon.com/tags/principal_tags/Claims',
            principal_tags_value=':brand.manage=1:scope=estate:',
            ttl_exp=9999999999,
            principal_tags_map={'brand.manage': '1', 'scope': 'estate', 'operator.manage': '1'},
        )
        payload = _b64url_json(token.split('.')[1])
        # The AWS tags claim is present with per-key principal_tags, array values.
        self.assertIn('https://aws.amazon.com/tags', payload)
        tags = payload['https://aws.amazon.com/tags']['principal_tags']
        self.assertEqual(tags['brand.manage'], ['1'])
        self.assertEqual(tags['scope'], ['estate'])
        self.assertEqual(tags['operator.manage'], ['1'])
        # The raw map takes PRECEDENCE: the legacy colon-string claim is NOT
        # also written (it would otherwise land as a stray "Claims" tag).
        self.assertNotIn('https://aws.amazon.com/tags/principal_tags/Claims', payload)

    def test_mint_falls_back_to_colon_string_when_no_map(self):
        # Backward compat: with no principal_tags_map, the legacy colon-string
        # claim is still written (for callers that have not migrated).
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        claim = 'https://aws.amazon.com/tags/principal_tags/Claims'
        token = wi.mint_web_identity_token(
            config, 'ap-southeast-2', subject='u',
            principal_tags_claim=claim, principal_tags_value=':brand=acme:',
            ttl_exp=9999999999,
        )
        payload = _b64url_json(token.split('.')[1])
        self.assertEqual(payload[claim], ':brand=acme:')
        self.assertNotIn('https://aws.amazon.com/tags', payload)

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

    def test_mint_carries_ui_permissions_and_scope(self):
        # The flat-permission model: the RS256 token carries ui_permissions (a
        # flat array, UI reflection only) and scope, forwarded from the
        # resolver's additional_claims.
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        token = wi.mint_web_identity_token(
            config, 'ap-southeast-2', subject='user-sub',
            principal_tags_claim=None, principal_tags_value=None,
            ttl_exp=9999999999,
            additional_claims={
                'ui_permissions': ['subject.read', 'list.manage'],
                'scope': 'brand:acme',
            },
        )
        payload = _b64url_json(token.split('.')[1])
        self.assertEqual(payload['ui_permissions'], ['subject.read', 'list.manage'])
        self.assertEqual(payload['scope'], 'brand:acme')

    def test_mint_carries_multi_key_principal_tags(self):
        # One session tag per granted permission (presence-only "1") plus the
        # brand tag, carried as a single multi-key :k=v: principal-tags string.
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        claim = 'https://aws.amazon.com/tags/principal_tags/Claims'
        token = wi.mint_web_identity_token(
            config, 'ap-southeast-2', subject='user-sub',
            principal_tags_claim=claim,
            principal_tags_value=':brand=acme:subject.read=1:list.manage=1:',
            ttl_exp=9999999999,
        )
        payload = _b64url_json(token.split('.')[1])
        self.assertEqual(
            payload[claim], ':brand=acme:subject.read=1:list.manage=1:')

    def test_mint_never_overwrites_reserved_or_tag_claims(self):
        # A resolver claim must never shadow a reserved claim or the tag claim.
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        claim = 'https://aws.amazon.com/tags/principal_tags/Claims'
        token = wi.mint_web_identity_token(
            config, 'ap-southeast-2', subject='real-sub',
            principal_tags_claim=claim,
            principal_tags_value=':brand=acme:',
            ttl_exp=9999999999,
            additional_claims={
                'sub': 'forged-sub',
                'exp': 1,
                claim: ':brand=evil:',
                'ui_permissions': ['subject.read'],
            },
        )
        payload = _b64url_json(token.split('.')[1])
        self.assertEqual(payload['sub'], 'real-sub')        # reserved, untouched
        self.assertEqual(payload['exp'], 9999999999)        # reserved, untouched
        self.assertEqual(payload[claim], ':brand=acme:')     # tag claim, untouched
        self.assertEqual(payload['ui_permissions'], ['subject.read'])  # non-reserved, carried

    def test_mint_refuses_when_over_budget(self):
        # Overflow at the ceiling REFUSES (ScopeTokenExceeds), never truncates —
        # so a partial tag set is never signed.
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        claim = 'https://aws.amazon.com/tags/principal_tags/Claims'
        big_tags = ':' + ':'.join(f'perm{i}=1' for i in range(400)) + ':'
        with self.assertRaises(wi.ScopeTokenExceeds):
            wi.mint_web_identity_token(
                config, 'ap-southeast-2', subject='user-sub',
                principal_tags_claim=claim,
                principal_tags_value=big_tags,
                ttl_exp=9999999999,
                max_bytes=1024,
            )

    def test_mint_allows_when_within_budget(self):
        # A normal one-brand token (brand tag + a few permission tags) fits well
        # under the ceiling and mints cleanly.
        config = {'web_identity_signing_key_id': 'key-1', 'web_identity_issuer': 'https://admin.example.com'}
        claim = 'https://aws.amazon.com/tags/principal_tags/Claims'
        token = wi.mint_web_identity_token(
            config, 'ap-southeast-2', subject='user-sub',
            principal_tags_claim=claim,
            principal_tags_value=':brand=acme:subject.read=1:list.manage=1:',
            ttl_exp=9999999999,
            additional_claims={'ui_permissions': ['subject.read', 'list.manage'], 'scope': 'brand:acme'},
            max_bytes=7168,
        )
        self.assertEqual(len(token.split('.')), 3)

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
