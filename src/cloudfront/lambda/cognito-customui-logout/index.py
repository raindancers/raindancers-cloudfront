"""Logout Lambda (Cognito custom-UI) — terminates a customer session completely.

Handles POST {logoutPath} (e.g. /oauth2/logout). Extracts the jti from the session
cookie, deletes the session and refresh-token records from DynamoDB, writes a
revocation entry to the CloudFront KeyValueStore (immediate edge rejection), revokes
the refresh token at Cognito, clears the session cookie, and redirects to a
first-party path.

POST only — CSRF is mitigated by SameSite=Lax on the session cookie (a cross-origin
form cannot submit with the cookie attached).
"""

import base64
import hashlib
import hmac
import json
import logging
import time

import boto3

from config_generated import get_config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = None
kvs_client = None
cognito_idp = None
CONFIG = None


def get_config_cached():
    global CONFIG, dynamodb, kvs_client, cognito_idp
    if CONFIG is None:
        CONFIG = get_config()
        region = CONFIG.get('dynamodb_region', 'us-east-1')
        dynamodb = boto3.client('dynamodb', region_name=region)
        kvs_client = boto3.client('cloudfront-keyvaluestore', region_name=region)
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
    """Verify HMAC signature (does NOT check exp — logout works on expired sessions)."""
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


def _read_edge_request(event):
    if 'Records' in event:
        request = event['Records'][0]['cf']['request']
        method = request.get('method', 'GET')
        cookies_raw = request.get('headers', {}).get('cookie', [{}])
        cookie_header = cookies_raw[0].get('value', '') if cookies_raw else ''
    else:
        method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
        cookie_header = event.get('cookies', [])
        cookie_header = '; '.join(cookie_header) if isinstance(cookie_header, list) else event.get('headers', {}).get('cookie', '')
    return method, cookie_header


def lambda_handler(event, context):
    method, cookie_header = _read_edge_request(event)

    if method != 'POST':
        return {'statusCode': 405, 'headers': {'Allow': 'POST', 'Content-Type': 'text/plain', 'Cache-Control': 'no-store'},
                'body': 'Method Not Allowed. Use POST.'}

    config = get_config_cached()
    post_logout_redirect = config.get('post_logout_redirect_path', '/')
    clear_auth_cookie = '__Host-auth_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'

    cookies = {}
    for cookie in cookie_header.split('; '):
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()

    session_token = cookies.get('__Host-auth_session') or cookies.get('__Secure-auth_session')
    if not session_token:
        return {'statusCode': 400, 'headers': {'Content-Type': 'text/plain', 'Cache-Control': 'no-store'},
                'body': 'No active session.'}

    hmac_secret = get_hmac_secret()
    payload = verify_hmac_jwt(session_token, hmac_secret)
    jti = payload.get('jti') if payload else None
    user_id = payload.get('sub', '') if payload else ''

    table_name = config.get('dynamodb_table_name')
    kvs_arn = config.get('kvs_arn', '')
    client_id = config.get('cognito_client_id', '')

    if jti and table_name:
        stored_refresh_token = None
        try:
            item = dynamodb.get_item(
                TableName=table_name,
                Key={'pk': {'S': f'REFRESH#{jti}'}, 'sk': {'S': f'REFRESH#{jti}'}},
            ).get('Item')
            if item:
                stored_refresh_token = item['refresh_token']['S']
        except Exception as e:
            logger.error(f'Failed to read refresh token: {e}')

        # Revoke the refresh token at Cognito (best-effort).
        if stored_refresh_token and client_id:
            try:
                cognito_idp.revoke_token(Token=stored_refresh_token, ClientId=client_id)
                logger.info(f'Cognito refresh token revoked for jti={jti}')
            except Exception as e:
                logger.error(f'Cognito revoke_token failed: {e}')

        try:
            dynamodb.delete_item(TableName=table_name, Key={'pk': {'S': f'REFRESH#{jti}'}, 'sk': {'S': f'REFRESH#{jti}'}})
        except Exception as e:
            logger.error(f'Failed to delete refresh token: {e}')

        if user_id:
            try:
                dynamodb.delete_item(TableName=table_name, Key={'pk': {'S': f'SESSION#{user_id}'}, 'sk': {'S': f'SESSION#{jti}'}})
            except Exception as e:
                logger.error(f'Failed to delete session record: {e}')

        # Immediate edge rejection via KVS denylist.
        if kvs_arn:
            try:
                kvs_client.put_key(KvsARN=kvs_arn, Key=f'revoked:{jti}', Value=str(int(time.time())), IfMatch='*')
                logger.info(f'Session revoked in KVS: revoked:{jti}')
            except Exception as e:
                logger.error(f'Failed to write KVS revocation: {e}')
    elif not payload:
        logger.warning('Invalid HMAC on session cookie during logout — clearing cookie without cleanup')

    logger.info(f'Logout complete for jti={jti}')
    return {
        'statusCode': 302,
        'headers': {'Location': post_logout_redirect, 'Cache-Control': 'no-store'},
        'multiValueHeaders': {'Set-Cookie': [clear_auth_cookie]},
    }
