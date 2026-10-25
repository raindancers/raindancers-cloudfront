"""
RS256 web-identity token: the role-assumption half of the two-token model.

The mint signs this token with an ASYMMETRIC KMS key (kms:Sign, RS256) so the
private key never leaves KMS. STS verifies it against the public half served at
the JWKS route, via sts:AssumeRoleWithWebIdentity. It carries the SAME
principal-tags brand claim as the HMAC session cookie, so AWS tags the assumed
role's session with the brand (DynamoDB LeadingKeys then enforces brand).

This is the asymmetric counterpart to the HMAC cookie: HMAC is validated offline
by the 10 KB edge CloudFront Function (which cannot call KMS); the RS256 token is
validated by STS (which requires an asymmetric token and refuses HMAC). One mint,
two tokens, each format forced by its verifier.

Signing is OFF unless the construct provisioned a key: web_identity_signing_key_id
must be present in config. When absent, is_enabled() is False and the mint emits
only the HMAC cookie, exactly as before.
"""

import base64
import json
import logging
import time
import uuid

import boto3

logger = logging.getLogger()

_KMS = None
_PUBLIC_KEY_CACHE = {}  # key_id -> jwk dict


def _kms(region):
    global _KMS
    if _KMS is None:
        _KMS = boto3.client('kms', region_name=region) if region else boto3.client('kms')
    return _KMS


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def is_enabled(config):
    """True when the construct provisioned the asymmetric key (feature on)."""
    return bool(config.get('web_identity_signing_key_id'))


def jwks_document(config, key_region):
    """Serve the JWKS: the web-identity key's public half as a single RSA JWK.

    Returns a CloudFront-shaped response dict. Lifted from the SCIM token
    service's jwks_document, reading the key id from the mint config.
    """
    key_id = config['web_identity_signing_key_id']
    jwk = _public_jwk(key_id, key_region)
    return {
        'status': '200',
        'statusDescription': 'OK',
        'headers': {
            'content-type': [{'key': 'Content-Type', 'value': 'application/json'}],
            'cache-control': [{'key': 'Cache-Control', 'value': 'public, max-age=3600'}],
        },
        'body': json.dumps({'keys': [jwk]}),
    }


def openid_configuration_document(config):
    """Serve the OIDC discovery document for the web-identity issuer.

    `sts:AssumeRoleWithWebIdentity` validates the token by discovering the
    issuer's keys: it GETs `<issuer>/.well-known/openid-configuration`, reads
    `jwks_uri`, then fetches that JWKS. Serving only `jwks.json` is not enough —
    without this document STS fails discovery with InvalidIdentityTokenException.

    The issuer is a self-issued provider (iss == aud), so the document advertises
    only what STS web-identity federation requires: the issuer, its jwks_uri, and
    the RS256 id_token signing algorithm. Returns a CloudFront-shaped response.
    """
    issuer = config['web_identity_issuer'].rstrip('/')
    doc = {
        'issuer': issuer,
        'jwks_uri': issuer + '/.well-known/jwks.json',
        'response_types_supported': ['id_token'],
        'subject_types_supported': ['public'],
        'id_token_signing_alg_values_supported': ['RS256'],
    }
    return {
        'status': '200',
        'statusDescription': 'OK',
        'headers': {
            'content-type': [{'key': 'Content-Type', 'value': 'application/json'}],
            'cache-control': [{'key': 'Cache-Control', 'value': 'public, max-age=3600'}],
        },
        'body': json.dumps(doc),
    }


def _public_jwk(key_id, key_region):
    """Fetch + cache the KMS asymmetric public key as a JWK (RS256, use=sig)."""
    if key_id in _PUBLIC_KEY_CACHE:
        return _PUBLIC_KEY_CACHE[key_id]
    resp = _kms(key_region).get_public_key(KeyId=key_id)
    der = resp['PublicKey']
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    pub = load_der_public_key(der)
    numbers = pub.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')
    jwk = {
        'kty': 'RSA',
        'use': 'sig',
        'alg': 'RS256',
        'kid': key_id,
        'n': _b64url(n),
        'e': _b64url(e),
    }
    _PUBLIC_KEY_CACHE[key_id] = jwk
    return jwk


def mint_web_identity_token(config, key_region, subject, principal_tags_claim, principal_tags_value, ttl_exp, username=None):
    """Mint a horton-signed RS256 web-identity JWT via KMS kms:Sign.

    - subject: the operator `sub` (same identity as the session cookie).
    - principal_tags_claim/value: the AWS principal-tags claim key + its already
      encoded `:k=v:` value (the SAME value stamped on the HMAC cookie), so the
      brand tag the two tokens carry can never disagree. Omitted when empty.
    - ttl_exp: absolute `exp` (unix), matched to the session cookie's expiry.
    - username: optional operator UPN (preferred_username) for SCIM resolution;
      added as the `preferred_username` claim when a non-empty string. `sub` is
      left unchanged (an opaque Entra pairwise id) so audit/trust are unaffected.

    Returns the compact JWS string. The caller delivers it to the client.
    """
    key_id = config['web_identity_signing_key_id']
    issuer = config['web_identity_issuer']
    now = int(time.time())
    header = {'alg': 'RS256', 'typ': 'JWT', 'kid': key_id}
    payload = {
        'iss': issuer,
        'aud': issuer,  # self-audience; role trust policy pins aud == iss
        'sub': subject,
        'iat': now,
        'nbf': now,
        'exp': ttl_exp,
        'jti': str(uuid.uuid4()),
    }
    if principal_tags_claim and principal_tags_value:
        payload[principal_tags_claim] = principal_tags_value
    if isinstance(username, str) and username:
        payload['preferred_username'] = username
    signing_input = (
        _b64url(json.dumps(header, separators=(',', ':')).encode())
        + '.'
        + _b64url(json.dumps(payload, separators=(',', ':')).encode())
    )
    # KMS signs RSASSA-PKCS1-v1_5 over SHA-256 (RS256). Message is the signing input.
    sig = _kms(key_region).sign(
        KeyId=key_id,
        Message=signing_input.encode('ascii'),
        MessageType='RAW',
        SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256',
    )['Signature']
    return signing_input + '.' + _b64url(sig)
