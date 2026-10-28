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


class ScopeTokenExceeds(Exception):
    """Raised when the assembled RS256 token would exceed the size ceiling.

    The flat-permission model carries one principal tag per granted permission
    plus the brand/scope tag inside the token (AssumeRoleWithWebIdentity has no
    Tags request param, so the tags ride in the claim). An assignment grid that
    cannot fit the ceiling signals a mismodelled assignment — the mint REFUSES
    (never truncates), so a partial tag set is never signed. The caller fails
    closed exactly as it already does for the HMAC half.
    """


def _rs256_assembled_len(header_b64, payload_b64):
    """Byte length of the assembled compact RS256 JWS: header + '.' + payload +
    '.' + the base64url signature segment. An RS256 signature over a 2048-bit
    key is 256 bytes, which base64url-encodes (no padding) to 342 bytes. Mirrors
    the HMAC guard's assembled-length arithmetic so both mints refuse on the
    SAME assembled-token ceiling rather than on payload size alone.
    """
    return len(header_b64) + 1 + len(payload_b64) + 1 + 342


def scope_token_exceeds(header_b64, payload_b64, max_bytes):
    """True when the assembled RS256 token is over `max_bytes` (refuse, never
    truncate). Same contract as the HMAC-side guard in oauth-callback.py."""
    return _rs256_assembled_len(header_b64, payload_b64) > max_bytes


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


def mint_web_identity_token(config, key_region, subject, principal_tags_claim, principal_tags_value, ttl_exp, username=None, additional_claims=None, max_bytes=None, principal_tags_map=None):
    """Mint a horton-signed RS256 web-identity JWT via KMS kms:Sign.

    - subject: the operator `sub` (same identity as the session cookie).
    - principal_tags_claim/value: LEGACY colon-string path. The AWS principal-
      tags claim key + its already-encoded `:k=v:` value (the SAME value stamped
      on the HMAC cookie). Retained for callers that have not migrated, but the
      colon-string does NOT produce per-key session tags at STS — see
      principal_tags_map below.
    - principal_tags_map: the RAW {name: value} tag map (the resolver's
      principal_tags). When provided, the token carries the AWS session-tags
      claim in the shape STS actually parses into per-key session tags:

          "https://aws.amazon.com/tags": {"principal_tags": {"<k>": ["<v>"], ...}}

      This is REQUIRED for the brand/permission tag fence to work:
      sts:AssumeRoleWithWebIdentity only sets aws:PrincipalTag/<k> for each key
      in this object. The legacy `:k=v:` colon-string, in contrast, STS stored as
      a SINGLE tag literally named "Claims" whose value was the whole string — so
      aws:PrincipalTag/brand.manage never existed and every brand-fenced policy
      condition failed with AccessDenied (proven 2026-10-28 via CloudTrail +
      KMS-signed probe: the object form assumes AND the real DynamoDB Query
      succeeds; the colon-string form is denied). The HMAC session cookie keeps
      the colon-string (its edge auth-check reads it that way); only the
      web_identity token the mint signs here switches to the object form.
      When principal_tags_map is given it takes precedence over
      principal_tags_claim/value.
    - ttl_exp: absolute `exp` (unix), matched to the session cookie's expiry.
    - username: optional operator UPN (preferred_username) for SCIM resolution;
      added as the `preferred_username` claim when a non-empty string. `sub` is
      left unchanged (an opaque Entra pairwise id) so audit/trust are unaffected.
    - additional_claims: optional {name: value} map of resolver-resolved claims
      to carry in the RS256 token — the flat `ui_permissions` array (UI
      reflection only) and `scope` ("brand:acme" | "estate"). The caller
      whitelist-gates this map before passing it, exactly like the HMAC side;
      the mint only writes what it is handed. Reserved claims (iss/aud/sub/iat/
      nbf/exp/jti and the principal-tags claim) are never overwritten.
    - max_bytes: optional assembled-token ceiling. When set, the mint REFUSES
      (raises ScopeTokenExceeds, never truncates) if the assembled token would
      exceed it — so an over-budget tag grid is never signed.

    Returns the compact JWS string. The caller delivers it to the client.
    """
    # The AWS-documented session-tags claim key STS parses into per-key tags.
    AWS_TAGS_CLAIM = 'https://aws.amazon.com/tags'
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
    _RESERVED = {'iss', 'aud', 'sub', 'iat', 'nbf', 'exp', 'jti'}
    if additional_claims:
        for name, value in additional_claims.items():
            if name in _RESERVED or name == principal_tags_claim or name == AWS_TAGS_CLAIM:
                continue  # never let a resolver claim shadow a reserved/tag claim
            payload[name] = value
    if principal_tags_map:
        # STS-correct session tags: one aws:PrincipalTag/<k> per entry. Values
        # are single-element string arrays per the AWS claim schema.
        payload[AWS_TAGS_CLAIM] = {
            'principal_tags': {
                str(k): [str(v)] for k, v in principal_tags_map.items()
            }
        }
    elif principal_tags_claim and principal_tags_value:
        # Legacy colon-string path (no per-key tags at STS; kept for compat).
        payload[principal_tags_claim] = principal_tags_value
    if isinstance(username, str) and username:
        payload['preferred_username'] = username
    header_b64 = _b64url(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(',', ':')).encode())
    if max_bytes is not None and scope_token_exceeds(header_b64, payload_b64, max_bytes):
        raise ScopeTokenExceeds(
            f'assembled web-identity token is '
            f'{_rs256_assembled_len(header_b64, payload_b64)} bytes, over '
            f'{max_bytes}; refusing mint'
        )
    signing_input = header_b64 + '.' + payload_b64
    # KMS signs RSASSA-PKCS1-v1_5 over SHA-256 (RS256). Message is the signing input.
    sig = _kms(key_region).sign(
        KeyId=key_id,
        Message=signing_input.encode('ascii'),
        MessageType='RAW',
        SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256',
    )['Signature']
    return signing_input + '.' + _b64url(sig)
