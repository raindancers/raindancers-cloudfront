"""Unit tests for the Entra mint's scope-token discipline (0.0.53).

These cover the two behaviours ported from the Cognito Scope Resolver onto the
Entra `oauth-callback.py` mint:

  1. Principal-tag encoding into the AWS principal-tags claim, in the `:k=v:`
     shape the Cognito resolver and the pre-token injector emit.
  2. The assembled-token size guard — refuse (never truncate) an over-budget
     token, using the SAME arithmetic as the Cognito mint so both refuse at the
     same ceiling.

The mint module imports `boto3`, `jwt` and `config_generated` at module scope;
`config_generated.get_config` reads a Secrets Manager value at CALL time, not at
import, so importing the module is side-effect free once `config_generated` is
importable. The file name has a hyphen, so it is loaded by path with importlib.
"""
import importlib.util
import os
import sys
import types
import unittest


def _load_mint_module():
    # Stub config_generated so importing the mint never needs AWS. The real one
    # only calls boto3 inside get_config(), which these tests never invoke.
    if 'config_generated' not in sys.modules:
        stub = types.ModuleType('config_generated')
        stub.get_config = lambda: {}
        sys.modules['config_generated'] = stub

    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, os.pardir, 'oauth-callback.py')
    spec = importlib.util.spec_from_file_location('entra_oauth_callback', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mint = _load_mint_module()


class PrincipalTagEncodingTests(unittest.TestCase):
    def test_single_tag_wraps_in_colons(self):
        self.assertEqual(mint.encode_principal_tags({'brand': 'acme'}), ':brand=acme:')

    def test_multiple_tags_colon_joined(self):
        # Insertion order is preserved (py3.7+ dict ordering).
        self.assertEqual(
            mint.encode_principal_tags({'brand': 'acme', 'tier': 'gold'}),
            ':brand=acme:tier=gold:',
        )

    def test_empty_map_returns_none(self):
        self.assertIsNone(mint.encode_principal_tags({}))
        self.assertIsNone(mint.encode_principal_tags(None))

    def test_claim_key_matches_cognito_resolver(self):
        self.assertEqual(
            mint.PRINCIPAL_TAGS_CLAIM,
            'https://aws.amazon.com/tags/principal_tags/Claims',
        )


class TokenSizeGuardTests(unittest.TestCase):
    def test_assembled_len_counts_both_dots_and_sig_segment(self):
        # header(10) + '.'(1) + payload(20) + '.'(1) + sig(43) = 75
        self.assertEqual(mint.assembled_token_len('x' * 10, 'y' * 20), 75)

    def test_under_budget_not_exceeded(self):
        self.assertFalse(mint.scope_token_exceeds('x' * 10, 'y' * 20, 7168))

    def test_over_budget_exceeded(self):
        big = 'y' * 8000
        self.assertTrue(mint.scope_token_exceeds('x' * 10, big, 7168))

    def test_boundary_is_strict_greater_than(self):
        # Exactly at the ceiling is allowed; one byte over is refused.
        header, payload = 'x' * 10, 'y' * 20
        exact = mint.assembled_token_len(header, payload)
        self.assertFalse(mint.scope_token_exceeds(header, payload, exact))
        self.assertTrue(mint.scope_token_exceeds(header, payload, exact - 1))

    def test_arithmetic_matches_cognito_mint(self):
        # The Cognito guard is: len(h) + 1 + len(p) + 1 + 43. Lock that both
        # mints compute the same assembled length for the same segments.
        for h_len, p_len in [(1, 1), (10, 20), (50, 6000)]:
            self.assertEqual(
                mint.assembled_token_len('h' * h_len, 'p' * p_len),
                h_len + 1 + p_len + 1 + 43,
            )


class HookSigV4Tests(unittest.TestCase):
    """The post-auth hook can SigV4-sign its request so an authority-minting
    resolver sits behind an IAM-gated Function URL instead of a public one."""

    def _fake_boto3(self):
        import types as _t

        class _Frozen:
            access_key = 'AKIAEXAMPLE'
            secret_key = 'secret'
            token = 'session-token'

        class _Creds:
            def get_frozen_credentials(self):
                return _Frozen()

        class _Session:
            region_name = 'ap-southeast-2'

            def get_credentials(self):
                return _Creds()

        fake = _t.ModuleType('boto3')
        fake.Session = lambda *a, **k: _Session()
        fake.__version__ = 'fake'
        return fake

    def test_sign_produces_sigv4_authorization_for_lambda_service(self):
        saved = mint.boto3
        mint.boto3 = self._fake_boto3()
        try:
            headers = mint._sigv4_sign_hook(
                'https://abc123.lambda-url.ap-southeast-2.on.aws/',
                b'{"sub":"x"}',
                'ap-southeast-2',
            )
        finally:
            mint.boto3 = saved
        auth = headers.get('Authorization', '')
        self.assertIn('AWS4-HMAC-SHA256', auth)
        # signed for the Lambda Function URL service in the given region.
        self.assertIn('/ap-southeast-2/lambda/aws4_request', auth)
        self.assertIn('X-Amz-Security-Token', headers)

    def test_sign_raises_without_credentials(self):
        import types as _t

        class _NoCredsSession:
            region_name = 'ap-southeast-2'

            def get_credentials(self):
                return None

        fake = _t.ModuleType('boto3')
        fake.Session = lambda *a, **k: _NoCredsSession()
        saved = mint.boto3
        mint.boto3 = fake
        try:
            with self.assertRaises(RuntimeError):
                mint._sigv4_sign_hook('https://x.on.aws/', b'{}', 'ap-southeast-2')
        finally:
            mint.boto3 = saved


if __name__ == '__main__':
    unittest.main()
