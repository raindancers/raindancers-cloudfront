"""Session-issuance Lambda — mints a first-party session for the custom-UI flow.

Handles POST {sessionIssuancePath} (e.g. /auth/session). The brand login page
performs Cognito SRP client-side, holds the resulting tokens in memory only, and
POSTs them here. This Lambda:

  1. Validates the Cognito id_token (RS256 against the pool JWKS).
  2. Calls the identity-linking hook to resolve/create the Medusa customer_id.
  3. Mints an HMAC-SHA256 session JWT and sets it as the __Host-auth_session cookie.
  4. Stores the session (SESSION#) and the refresh token (REFRESH#) server-side.

Cognito tokens are NEVER returned to or stored by the browser: the only credential
that leaves this Lambda is the HttpOnly session cookie. Runs as a Lambda@Edge
origin-request with includeBody=true (so it can read the POSTed tokens).

POST only — CSRF is mitigated by SameSite=Lax on the session cookie and by the
fact that the endpoint requires a JSON body the browser only sends same-origin.
"""

import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime

import boto3
import jwt
from jwt import PyJWK

from config_generated import get_config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = None
secretsmanager = None
CONFIG = None
HMAC_SECRET = None
HOOK_SECRET = None
JWKS_CACHE = None


def get_config_cached():
    global CONFIG, dynamodb, secretsmanager
    if CONFIG is None:
        CONFIG = get_config()
        region = CONFIG.get('dynamodb_region', 'us-east-1')
        dynamodb = boto3.client('dynamodb', region_name=region)
        secretsmanager = boto3.client('secretsmanager', region_name=CONFIG.get('config_region', region))
    return CONFIG


def get_hmac_secret():
    global HMAC_SECRET
    if HMAC_SECRET is None:
        HMAC_SECRET = get_config_cached().get('hmac_key')
        if not HMAC_SECRET:
            raise ValueError('hmac_key not found in config')
    return HMAC_SECRET


def get_hook_secret():
    """Fetch the identity-hook shared secret from Secrets Manager (cached)."""
    global HOOK_SECRET
    if HOOK_SECRET is not None:
        return HOOK_SECRET
    config = get_config_cached()
    arn = config.get('post_auth_hook_secret_arn', '')
    if not arn:
        HOOK_SECRET = ''
        return HOOK_SECRET
    resp = secretsmanager.get_secret_value(SecretId=arn)
    HOOK_SECRET = resp.get('SecretString', '')
    return HOOK_SECRET


def base64url_encode(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def validate_id_token(id_token, client_id, user_pool_id, cognito_region):
    """Validate a Cognito id_token: RS256, correct audience and issuer."""
    global JWKS_CACHE
    if JWKS_CACHE is None:
        jwks_url = f'https://cognito-idp.{cognito_region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'
        with urllib.request.urlopen(jwks_url, timeout=5) as response:
            JWKS_CACHE = json.loads(response.read().decode('utf-8'))

    unverified_header = jwt.get_unverified_header(id_token)
    rsa_key = next((k for k in JWKS_CACHE['keys'] if k['kid'] == unverified_header['kid']), None)
    if not rsa_key:
        raise ValueError('No matching JWKS key for token kid')

    jwk = PyJWK.from_dict(rsa_key)
    issuer = f'https://cognito-idp.{cognito_region}.amazonaws.com/{user_pool_id}'
    return jwt.decode(id_token, jwk.key, algorithms=['RS256'], audience=client_id, issuer=issuer)


def call_identity_hook(hook_url, identity):
    """Call the identity-linking hook. Returns (status_code, body_dict)."""
    data = json.dumps(identity, separators=(',', ':')).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    secret = get_hook_secret()
    if secret:
        headers['Authorization'] = f'Bearer {secret}'
    req = urllib.request.Request(hook_url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.getcode(), json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = {}
        try:
            body = json.loads(e.read().decode('utf-8'))
        except Exception:
            pass
        return e.code, body


def _parse_body(request):
    """Extract the POSTed JSON body from a Lambda@Edge or Function URL event."""
    body = request.get('body', {})
    if isinstance(body, dict):
        raw = body.get('data', '')
        if body.get('encoding') == 'base64' and raw:
            raw = base64.b64decode(raw).decode('utf-8')
    else:
        raw = body or ''
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _sanitise_return_to(return_to, allowed_domains):
    """Only permit relative paths, or absolute URLs on an allowed domain."""
    if not return_to:
        return '/'
    if return_to.startswith('//') or return_to.startswith('/\\'):
        return '/'
    if return_to.startswith('http'):
        parsed = urllib.parse.urlparse(return_to)
        if parsed.hostname and parsed.hostname in allowed_domains:
            return return_to
        return '/'
    if not return_to.startswith('/'):
        return '/'
    return return_to[:2048]


def _json_response(status, obj, extra_headers=None):
    headers = {
        'content-type': [{'key': 'Content-Type', 'value': 'application/json'}],
        'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}],
    }
    if extra_headers:
        headers.update(extra_headers)
    return {'status': str(status), 'statusDescription': 'OK', 'headers': headers,
            'body': json.dumps(obj)}


def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']

    if request.get('method', 'GET') != 'POST':
        return _json_response(405, {'error': 'method_not_allowed'})

    try:
        config = get_config_cached()
        client_id = config['cognito_client_id']
        user_pool_id = config['cognito_user_pool_id']
        cognito_region = config['cognito_region']
        table_name = config.get('dynamodb_table_name')
        hook_url = config.get('post_auth_hook_url', '')
        allowed_domains = json.loads(config.get('allowed_domains', '[]'))
        session_ttl = int(config.get('session_ttl_seconds', '3600'))
        refresh_ttl_days = int(config.get('refresh_ttl_days', '30'))
    except Exception as e:
        logger.error(f'Config load failed: {e}')
        return _json_response(500, {'error': 'config_error'})

    body = _parse_body(request)
    id_token = body.get('id_token')
    refresh_token = body.get('refresh_token')
    return_to = _sanitise_return_to(body.get('return_to', '/'), allowed_domains)

    if not id_token:
        return _json_response(400, {'error': 'missing_id_token'})

    # 1. Validate the Cognito id_token.
    try:
        claims = validate_id_token(id_token, client_id, user_pool_id, cognito_region)
    except Exception as e:
        logger.warning(f'id_token validation failed: {e}')
        return _json_response(401, {'error': 'invalid_token'})

    sub = claims.get('sub')
    email = claims.get('email', '')
    if not sub:
        return _json_response(401, {'error': 'invalid_token'})

    # 2. Resolve the Medusa customer via the identity-linking hook.
    customer_id = ''
    if hook_url:
        status, hook_body = call_identity_hook(hook_url, {
            'sub': sub, 'email': email, 'provider': 'cognito',
        })
        if status == 409:
            # Social/local conflict — do not issue a session.
            return _json_response(409, {'error': 'identity_conflict'})
        if status < 200 or status >= 300 or 'customer_id' not in hook_body:
            logger.error(f'Identity hook failed: status={status} body={hook_body}')
            return _json_response(503, {'error': 'identity_unavailable'})
        customer_id = hook_body['customer_id']

    # 3. Mint the HMAC session JWT.
    jti = f'sess_{uuid.uuid4().hex}'
    now = int(time.time())
    exp = now + session_ttl
    session_payload = {
        'sub': sub,
        'email': email,
        'customer_id': customer_id,
        'jti': jti,
        'iat': now,
        'exp': exp,
        'iss': claims.get('iss', ''),
    }
    if claims.get('cognito:groups'):
        session_payload['roles'] = claims['cognito:groups']

    hmac_secret = get_hmac_secret()
    header_b64 = base64url_encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    payload_b64 = base64url_encode(json.dumps(session_payload, separators=(',', ':')).encode())
    signing_input = f'{header_b64}.{payload_b64}'
    sig = hmac.new(hmac_secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    cookie_value = f'{signing_input}.{base64url_encode(sig)}'

    # 4. Persist session + refresh token server-side.
    if table_name:
        try:
            dynamodb.put_item(TableName=table_name, Item={
                'pk': {'S': f'SESSION#{sub}'}, 'sk': {'S': f'SESSION#{jti}'},
                'gsi1pk': {'S': f'USER#{sub}'}, 'gsi1sk': {'S': f'SESSION#{now}'},
                'jti': {'S': jti}, 'userId': {'S': sub}, 'email': {'S': email},
                'customer_id': {'S': customer_id},
                'createdAt': {'N': str(now)}, 'revoked': {'BOOL': False},
                'expiresAt': {'N': str(exp)},
            })
            if refresh_token:
                refresh_exp = now + refresh_ttl_days * 86400
                dynamodb.put_item(TableName=table_name, Item={
                    'pk': {'S': f'REFRESH#{jti}'}, 'sk': {'S': f'REFRESH#{jti}'},
                    'refresh_token': {'S': refresh_token},
                    'user_id': {'S': sub}, 'customer_id': {'S': customer_id},
                    'createdAt': {'N': str(now)}, 'expiresAt': {'N': str(refresh_exp)},
                })
        except Exception as e:
            logger.error(f'Failed to persist session/refresh: {e}')
            return _json_response(503, {'error': 'session_store_unavailable'})

    expires_str = datetime.utcfromtimestamp(exp).strftime('%a, %d %b %Y %H:%M:%S GMT')
    set_cookie = (f'__Host-auth_session={cookie_value}; HttpOnly; Secure; '
                  f'SameSite=Lax; Path=/; Expires={expires_str}')
    return _json_response(200, {'redirect': return_to}, extra_headers={
        'set-cookie': [{'key': 'Set-Cookie', 'value': set_cookie}],
    })
