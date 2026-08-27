"""Refresh Lambda (Cognito custom-UI) — silently renews expired sessions.

Handles GET {refreshPath} (e.g. /oauth2/refresh?return_to={url}). Extracts the jti
from the expired-but-HMAC-valid session cookie, retrieves the stored Cognito refresh
token from DynamoDB, calls Cognito InitiateAuth REFRESH_TOKEN_AUTH to obtain fresh
tokens, mints a new HMAC session JWT, and redirects back to return_to with a fresh
session cookie.

Cognito rotates the refresh token only if refresh-token rotation is enabled on the
app client. This Lambda handles both cases: if InitiateAuth returns a new RefreshToken
it is rotated (old record deleted); otherwise the existing token is re-keyed under the
new jti. If the refresh token is invalid/expired, the customer is redirected to /login.
"""

import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.parse
import uuid
from datetime import datetime

import boto3

from config_generated import get_config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = None
cognito_idp = None
CONFIG = None


def get_config_cached():
    global CONFIG, dynamodb, cognito_idp
    if CONFIG is None:
        CONFIG = get_config()
        region = CONFIG.get('dynamodb_region', 'us-east-1')
        dynamodb = boto3.client('dynamodb', region_name=region)
        cognito_idp = boto3.client('cognito-idp', region_name=CONFIG.get('cognito_region', region))
    return CONFIG


def get_hmac_secret():
    secret = get_config_cached().get('hmac_key')
    if not secret:
        raise ValueError('hmac_key not found in config')
    return secret


def base64url_decode(s):
    s = s + '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def base64url_encode(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def verify_hmac_jwt(token, secret):
    """Verify HMAC signature (does NOT check exp — token is expected expired)."""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    signing_input = f'{parts[0]}.{parts[1]}'
    expected = base64url_encode(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, parts[2]):
        return None
    try:
        return json.loads(base64url_decode(parts[1]))
    except Exception:
        return None


def issue_session_jwt(payload_claims, secret):
    header_b64 = base64url_encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    payload_b64 = base64url_encode(json.dumps(payload_claims, separators=(',', ':')).encode())
    signing_input = f'{header_b64}.{payload_b64}'
    sig = base64url_encode(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest())
    return f'{signing_input}.{sig}'


def cognito_refresh(refresh_token, client_id):
    """Exchange a Cognito refresh token for new tokens via InitiateAuth."""
    resp = cognito_idp.initiate_auth(
        ClientId=client_id,
        AuthFlow='REFRESH_TOKEN_AUTH',
        AuthParameters={'REFRESH_TOKEN': refresh_token},
    )
    return resp.get('AuthenticationResult', {})


def login_redirect(config, return_to='/'):
    login_path = config.get('login_redirect_path', '/login')
    return f'{login_path}?returnTo={urllib.parse.quote(return_to)}'


def _read_edge_request(event):
    if 'Records' in event:
        request = event['Records'][0]['cf']['request']
        query_string = request.get('querystring', '')
        cookies_raw = request.get('headers', {}).get('cookie', [{}])
        cookie_header = cookies_raw[0].get('value', '') if cookies_raw else ''
    else:
        query_string = event.get('rawQueryString', '')
        cookie_header = event.get('cookies', [])
        cookie_header = '; '.join(cookie_header) if isinstance(cookie_header, list) else event.get('headers', {}).get('cookie', '')
    return query_string, cookie_header


def redirect_response(location, clear_session=False):
    headers = {'Location': location, 'Cache-Control': 'no-store'}
    if clear_session:
        headers['Set-Cookie'] = '__Host-auth_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
    return {'statusCode': 302, 'headers': headers}


def error_response(status_code, message):
    return {'statusCode': status_code, 'headers': {'Content-Type': 'text/plain', 'Cache-Control': 'no-store'}, 'body': message}


def lambda_handler(event, context):
    query_string, cookie_header = _read_edge_request(event)
    config = get_config_cached()

    params = urllib.parse.parse_qs(query_string)
    return_to = params.get('return_to', ['/'])[0]
    if return_to.startswith('http'):
        allowed = json.loads(config.get('allowed_domains', '[]'))
        parsed = urllib.parse.urlparse(return_to)
        if parsed.hostname and parsed.hostname not in allowed:
            logger.warning(f'Open redirect blocked: {return_to}')
            return_to = '/'

    cookies = {}
    for cookie in cookie_header.split('; '):
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()

    session_token = cookies.get('__Host-auth_session') or cookies.get('__Secure-auth_session')
    if not session_token:
        return redirect_response(login_redirect(config, return_to))

    hmac_secret = get_hmac_secret()
    payload = verify_hmac_jwt(session_token, hmac_secret)
    if not payload or not payload.get('jti'):
        return redirect_response(login_redirect(config, return_to), clear_session=True)

    jti = payload['jti']
    table_name = config.get('dynamodb_table_name')
    client_id = config['cognito_client_id']

    try:
        item = dynamodb.get_item(
            TableName=table_name,
            Key={'pk': {'S': f'REFRESH#{jti}'}, 'sk': {'S': f'REFRESH#{jti}'}},
        ).get('Item')
        if not item:
            return redirect_response(login_redirect(config, return_to), clear_session=True)
        stored_refresh_token = item['refresh_token']['S']
    except Exception as e:
        logger.error(f'DynamoDB error retrieving refresh token: {e}')
        return error_response(503, 'Service temporarily unavailable')

    try:
        result = cognito_refresh(stored_refresh_token, client_id)
    except Exception as e:
        logger.error(f'Cognito refresh failed: {e}')
        return redirect_response(login_redirect(config, return_to), clear_session=True)

    session_ttl = int(config.get('session_ttl_seconds', '3600'))
    refresh_ttl_days = int(config.get('refresh_ttl_days', '30'))
    now = int(time.time())
    new_jti = f'sess_{uuid.uuid4().hex}'
    new_exp = now + min(int(result.get('ExpiresIn', session_ttl)), session_ttl)

    new_payload = {**payload, 'jti': new_jti, 'exp': new_exp, 'iat': now}
    new_session_jwt = issue_session_jwt(new_payload, hmac_secret)

    # Rotate if Cognito returned a new refresh token; otherwise re-key the existing one.
    new_refresh_token = result.get('RefreshToken', stored_refresh_token)
    user_id = payload.get('sub', '')
    customer_id = payload.get('customer_id', item.get('customer_id', {}).get('S', ''))
    try:
        dynamodb.put_item(TableName=table_name, Item={
            'pk': {'S': f'REFRESH#{new_jti}'}, 'sk': {'S': f'REFRESH#{new_jti}'},
            'refresh_token': {'S': new_refresh_token},
            'user_id': {'S': user_id}, 'customer_id': {'S': customer_id},
            'createdAt': {'N': str(now)}, 'expiresAt': {'N': str(now + refresh_ttl_days * 86400)},
        })
        dynamodb.delete_item(TableName=table_name, Key={'pk': {'S': f'REFRESH#{jti}'}, 'sk': {'S': f'REFRESH#{jti}'}})
        dynamodb.put_item(TableName=table_name, Item={
            'pk': {'S': f'SESSION#{user_id}'}, 'sk': {'S': f'SESSION#{new_jti}'},
            'gsi1pk': {'S': f'USER#{user_id}'}, 'gsi1sk': {'S': f'SESSION#{now}'},
            'jti': {'S': new_jti}, 'userId': {'S': user_id}, 'email': {'S': payload.get('email', '')},
            'customer_id': {'S': customer_id},
            'createdAt': {'N': str(now)}, 'revoked': {'BOOL': False}, 'expiresAt': {'N': str(new_exp)},
        })
    except Exception as e:
        logger.error(f'DynamoDB error during refresh rotation: {e}')

    expires_str = datetime.utcfromtimestamp(new_exp).strftime('%a, %d %b %Y %H:%M:%S GMT')
    auth_cookie = (f'__Host-auth_session={new_session_jwt}; HttpOnly; Secure; '
                   f'SameSite=Lax; Path=/; Expires={expires_str}')
    logger.info(f'Session refreshed: {jti} -> {new_jti}')
    return {'statusCode': 302, 'headers': {'Location': return_to, 'Set-Cookie': auth_cookie, 'Cache-Control': 'no-store'}}
