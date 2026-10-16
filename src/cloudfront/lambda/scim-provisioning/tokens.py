"""
Token endpoint, access-token minting, and JWKS.

Access tokens are RS256 JWTs SIGNED BY KMS (kms:Sign) so the private key never
leaves KMS; the public half is served at the JWKS route and used by the SCIM
handler (and any external verifier) to verify tokens by signature. The OAuth 2.0
client-credentials grant is the day-one path; the WIF (RFC 7523 JWT bearer
assertion) branch shares the same minting half and is selected by AUTH_MODE=WIF.
"""

import base64
import hmac
import json
import logging
import os
import time
import urllib.parse
import urllib.request
import uuid

import boto3
import jwt

logger = logging.getLogger()

_KMS = None
_PUBLIC_KEY_CACHE = {}   # key_id -> (jwk dict, pem public key)
_JWKS_CACHE = {}         # jwks_uri -> {kid: public_key}


def _kms():
    global _KMS
    if _KMS is None:
        _KMS = boto3.client('kms')
    return _KMS


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _json_resp(status, body):
    return {
        'statusCode': status,
        'headers': {'content-type': 'application/json', 'cache-control': 'no-store'},
        'body': json.dumps(body),
    }


# ------------------------------------------------------------ public key / JWKS

def _kms_public_key(key_id):
    """Fetch + cache the KMS asymmetric public key as (jwk, pem)."""
    if key_id in _PUBLIC_KEY_CACHE:
        return _PUBLIC_KEY_CACHE[key_id]
    resp = _kms().get_public_key(KeyId=key_id)
    der = resp['PublicKey']
    from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
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
    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    _PUBLIC_KEY_CACHE[key_id] = (jwk, pem)
    return _PUBLIC_KEY_CACHE[key_id]


def jwks_document():
    key_id = os.environ['SIGNING_KEY_ID']
    jwk, _ = _kms_public_key(key_id)
    return {
        'statusCode': 200,
        'headers': {'content-type': 'application/json'},
        'body': json.dumps({'keys': [jwk]}),
    }


# ------------------------------------------------------------ minting (KMS RS256)

def mint_access_token(subject):
    """Mint a short-lived RS256 JWT signed by KMS."""
    key_id = os.environ['SIGNING_KEY_ID']
    issuer = os.environ['TOKEN_ISSUER']
    ttl = int(os.environ.get('ACCESS_TOKEN_TTL', '3600'))
    now = int(time.time())
    header = {'alg': 'RS256', 'typ': 'JWT', 'kid': key_id}
    payload = {
        'iss': issuer,
        'aud': issuer,       # self-audience; the SCIM handler requires aud == iss
        'sub': subject,
        'iat': now,
        'nbf': now,
        'exp': now + ttl,
        'jti': str(uuid.uuid4()),
    }
    signing_input = (_b64url(json.dumps(header, separators=(',', ':')).encode())
                     + '.'
                     + _b64url(json.dumps(payload, separators=(',', ':')).encode()))
    # KMS signs RSASSA-PKCS1-v1_5 over SHA-256 (RS256). Message is the signing input.
    sig = _kms().sign(
        KeyId=key_id,
        Message=signing_input.encode('ascii'),
        MessageType='RAW',
        SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256',
    )['Signature']
    token = signing_input + '.' + _b64url(sig)
    return token, ttl


def verify_access_token(token):
    """Verify a token we issued, against our own KMS public key. Returns claims or None."""
    try:
        key_id = os.environ['SIGNING_KEY_ID']
        issuer = os.environ['TOKEN_ISSUER']
        _, pem = _kms_public_key(key_id)
        return jwt.decode(token, pem, algorithms=['RS256'], audience=issuer, issuer=issuer)
    except Exception as e:  # noqa: BLE001 - any verify failure is a denial
        logger.info('access token verification failed: %s', type(e).__name__)
        return None


# ------------------------------------------------------------ secret access

def _secret_value(arn):
    sm = boto3.client('secretsmanager')
    return sm.get_secret_value(SecretId=arn)['SecretString']


# ------------------------------------------------------------ token endpoint

def _form(event):
    raw = event.get('body') or ''
    if event.get('isBase64Encoded'):
        raw = base64.b64decode(raw).decode('utf-8')
    out = {}
    for pair in raw.split('&'):
        if not pair:
            continue
        k, _, v = pair.partition('=')
        out[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
    return out



def _basic_credentials(headers):
    """Extract (client_id, client_secret) from an HTTP Basic Authorization header."""
    auth = headers.get('authorization', '')
    if not auth.lower().startswith('basic '):
        return None, None
    try:
        decoded = base64.b64decode(auth[6:]).decode('utf-8')
        cid, _, secret = decoded.partition(':')
        return cid, secret
    except Exception:  # noqa: BLE001
        return None, None


def token_endpoint(event, headers):
    auth_mode = os.environ.get('AUTH_MODE', 'OAUTH_CLIENT_CREDENTIALS')
    form = _form(event)
    grant = form.get('grant_type')

    if grant != 'client_credentials':
        logger.info('token endpoint: unsupported grant_type=%r', grant)
        return _json_resp(400, {'error': 'unsupported_grant_type'})

    if auth_mode == 'WIF':
        return _wif_exchange(form)
    return _client_credentials_exchange(form, headers)


def _client_credentials_exchange(form, headers):
    # Extract creds from Basic header AND/OR body. Entra is known to send BOTH;
    # strict servers reject that. We accept when they agree and reject-with-log
    # only when they genuinely disagree.
    basic_id, basic_secret = _basic_credentials(headers)
    body_id, body_secret = form.get('client_id'), form.get('client_secret')

    client_id, client_secret, source = _reconcile_credentials(
        basic_id, basic_secret, body_id, body_secret)
    if client_id is None:
        logger.info('token endpoint: missing client credentials')
        return _json_resp(401, {'error': 'invalid_client', 'error_description': 'missing client credentials'})
    if source == 'conflict':
        logger.info('token endpoint: conflicting client credentials in header vs body')
        return _json_resp(401, {'error': 'invalid_client', 'error_description': 'conflicting client credentials'})

    logger.info('token endpoint: client_credentials grant for client_id=%s (creds via %s)', client_id, source)

    expected = _secret_value(os.environ['CLIENT_SECRET_ARN'])
    if not hmac.compare_digest(client_secret or '', expected or ''):
        logger.info('token endpoint: invalid client secret for client_id=%s', client_id)
        return _json_resp(401, {'error': 'invalid_client'})

    token, ttl = mint_access_token(subject=client_id)
    logger.info('token endpoint: issued token for client_id=%s ttl=%ss', client_id, ttl)
    return _json_resp(200, {'access_token': token, 'token_type': 'Bearer', 'expires_in': ttl})


def _reconcile_credentials(basic_id, basic_secret, body_id, body_secret):
    """
    Returns (client_id, client_secret, source) where source is 'header', 'body',
    'both', or 'conflict'. Tolerates Entra sending credentials in BOTH places.
    """
    have_basic = basic_id is not None and basic_secret is not None
    have_body = body_id is not None and body_secret is not None

    if have_basic and have_body:
        if basic_id == body_id and basic_secret == body_secret:
            return basic_id, basic_secret, 'both'
        # Entra sends identical creds in both; genuinely different values are a conflict.
        return basic_id, basic_secret, 'conflict'
    if have_basic:
        return basic_id, basic_secret, 'header'
    if have_body:
        return body_id, body_secret, 'body'
    return None, None, 'none'


# ------------------------------------------------------------ WIF branch (RFC 7523)

def _wif_exchange(form):
    assertion = form.get('client_assertion')
    assertion_type = form.get('client_assertion_type')
    if assertion_type != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' or not assertion:
        return _json_resp(400, {'error': 'invalid_request', 'error_description': 'jwt-bearer client_assertion required'})

    issuer = os.environ['WIF_ASSERTION_ISSUER']
    jwks_uri = os.environ['WIF_ASSERTION_JWKS_URI']
    audience = os.environ['WIF_EXPECTED_AUDIENCE']
    expected_azp = os.environ['WIF_EXPECTED_AZP']

    claims = _verify_wif_assertion(assertion, issuer, jwks_uri, audience)
    if claims is None:
        return _json_resp(401, {'error': 'invalid_client', 'error_description': 'assertion verification failed'})
    if claims.get('azp') != expected_azp:
        logger.info('WIF: azp mismatch')
        return _json_resp(401, {'error': 'invalid_client', 'error_description': 'azp mismatch'})

    subject = claims.get('azp') or claims.get('sub')
    token, ttl = mint_access_token(subject=subject)
    logger.info('WIF: issued token for azp=%s ttl=%ss', subject, ttl)
    return _json_resp(200, {'access_token': token, 'token_type': 'Bearer', 'expires_in': ttl})


def _idp_public_key(jwks_uri, kid):
    """Fetch + cache the IdP signing key for a kid (cache keyed by jwks_uri)."""
    cache = _JWKS_CACHE.get(jwks_uri, {})
    if kid in cache:
        return cache[kid]
    with urllib.request.urlopen(jwks_uri, timeout=5) as r:  # noqa: S310 - fixed https IdP JWKS
        doc = json.loads(r.read().decode('utf-8'))
    keys = {}
    for k in doc.get('keys', []):
        try:
            keys[k['kid']] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
        except Exception:  # noqa: BLE001
            continue
    _JWKS_CACHE[jwks_uri] = keys
    return keys.get(kid)


def _verify_wif_assertion(assertion, issuer, jwks_uri, audience):
    try:
        header = jwt.get_unverified_header(assertion)
        key = _idp_public_key(jwks_uri, header.get('kid'))
        if key is None:
            logger.info('WIF: no matching kid in IdP JWKS')
            return None
        return jwt.decode(assertion, key, algorithms=['RS256'], audience=audience, issuer=issuer)
    except Exception as e:  # noqa: BLE001
        logger.info('WIF: assertion verify failed: %s', type(e).__name__)
        return None
