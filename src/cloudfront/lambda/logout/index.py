"""Logout Lambda — terminates customer sessions completely.

Handles POST /oauth2/logout. Extracts the session ID (jti) from the session cookie,
deletes session and refresh token records from DynamoDB, writes a revocation entry
to the CloudFront KeyValueStore (immediate edge rejection), clears the session cookie,
and redirects to Entra's /logout endpoint for server-side session termination.

Only accepts POST requests (CSRF protection via SameSite cookie attribute).
"""

import json
import urllib.parse
import boto3
import logging
import hmac
import hashlib
import base64
import time
from config_generated import get_config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Lazy-initialised clients
dynamodb = None
kvs_client = None
CONFIG = None


def get_config_cached():
    """Load and cache configuration from Secrets Manager."""
    global CONFIG, dynamodb, kvs_client
    if CONFIG is None:
        CONFIG = get_config()
        dynamodb_region = CONFIG.get('dynamodb_region', 'us-east-1')
        dynamodb = boto3.client('dynamodb', region_name=dynamodb_region)
        kvs_client = boto3.client('cloudfront-keyvaluestore', region_name=dynamodb_region)
        logger.info(f'Clients initialised for region: {dynamodb_region}')
    return CONFIG


def get_hmac_secret():
    """Retrieve the HMAC signing secret from config."""
    config = get_config_cached()
    secret = config.get('hmac_key')
    if not secret:
        raise ValueError('hmac_key not found in config')
    return secret


def base64url_decode(s):
    """Decode a base64url-encoded string to bytes."""
    s = s + '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def base64url_encode(data):
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def verify_hmac_jwt(token, secret):
    """Verify HMAC-SHA256 JWT signature and return decoded payload.

    Does NOT check exp — logout should work even with expired sessions.

    Args:
        token: The raw JWT string (header.payload.signature).
        secret: The HMAC signing secret.

    Returns:
        Decoded payload dict if signature is valid, None otherwise.
    """
    parts = token.split('.')
    if len(parts) != 3:
        return None

    signing_input = f'{parts[0]}.{parts[1]}'
    expected_sig = hmac.new(
        secret.encode('utf-8'),
        signing_input.encode('utf-8'),
        hashlib.sha256
    ).digest()
    expected_sig_b64 = base64url_encode(expected_sig)

    provided_sig = parts[2]
    if not hmac.compare_digest(expected_sig_b64, provided_sig):
        return None

    try:
        payload_json = base64url_decode(parts[1])
        return json.loads(payload_json)
    except Exception:
        return None


def lambda_handler(event, context):
    """Handle logout requests: POST /oauth2/logout.

    Accepts POST only (enforced here — CSRF protection via SameSite=Lax cookie means
    cross-origin forms cannot submit to this endpoint with the session cookie attached).
    """
    # Determine request method and parse cookies
    if 'Records' in event:
        # Lambda@Edge format
        request = event['Records'][0]['cf']['request']
        method = request.get('method', 'GET')
        cookies_raw = request.get('headers', {}).get('cookie', [{}])
        cookie_header = cookies_raw[0].get('value', '') if cookies_raw else ''
    else:
        # Function URL format
        method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
        cookie_header = event.get('cookies', [])
        if isinstance(cookie_header, list):
            cookie_header = '; '.join(cookie_header)
        else:
            cookie_header = event.get('headers', {}).get('cookie', '')

    # Enforce POST method
    if method != 'POST':
        return {
            'statusCode': 405,
            'headers': {
                'Allow': 'POST',
                'Content-Type': 'text/plain',
                'Cache-Control': 'no-store',
            },
            'body': 'Method Not Allowed. Use POST.',
        }

    config = get_config_cached()
    cookie_domain = config.get('cookie_domain', '')
    domain_attr = f'; Domain={cookie_domain}' if cookie_domain else ''
    cookie_prefix = '__Secure-' if cookie_domain else '__Host-'

    # Parse session cookie
    cookies = {}
    for cookie in cookie_header.split('; '):
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()

    session_token = cookies.get('__Secure-auth_session') or cookies.get('__Host-auth_session')

    # Build cookie-clearing header (always clear, even if JWT is invalid)
    clear_auth_cookie = (
        f'{cookie_prefix}auth_session=; '
        f'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
        f'{domain_attr}'
    )
    clear_azure_cookie = (
        f'{cookie_prefix}azure_token=; '
        f'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
        f'{domain_attr}'
    )

    if not session_token:
        logger.warning('No session cookie in logout request')
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'text/plain',
                'Cache-Control': 'no-store',
            },
            'body': 'No active session.',
        }

    # Verify HMAC to extract jti (don't check exp — logout works on expired sessions too)
    hmac_secret = get_hmac_secret()
    payload = verify_hmac_jwt(session_token, hmac_secret)

    jti = None
    user_id = None
    if payload:
        jti = payload.get('jti')
        user_id = payload.get('sub', '')
    else:
        # Invalid HMAC — can't trust jti, but still clear the cookie
        logger.warning('Invalid HMAC on session cookie during logout — clearing cookie without DynamoDB cleanup')

    table_name = config.get('dynamodb_table_name')
    kvs_arn = config.get('kvs_arn', '')

    # Delete DynamoDB records (session + refresh token) if we have a valid jti
    if jti and table_name:
        # Delete refresh token
        try:
            dynamodb.delete_item(
                TableName=table_name,
                Key={'pk': {'S': f'REFRESH#{jti}'}, 'sk': {'S': f'REFRESH#{jti}'}}
            )
            logger.info(f'Refresh token deleted: REFRESH#{jti}')
        except Exception as e:
            logger.error(f'Failed to delete refresh token: {e}')

        # Delete session record
        if user_id:
            try:
                dynamodb.delete_item(
                    TableName=table_name,
                    Key={'pk': {'S': f'SESSION#{user_id}'}, 'sk': {'S': f'SESSION#{jti}'}}
                )
                logger.info(f'Session record deleted: SESSION#{user_id}/SESSION#{jti}')
            except Exception as e:
                logger.error(f'Failed to delete session record: {e}')

        # Write revocation to KVS for immediate edge rejection
        if kvs_arn:
            try:
                kvs_client.put_key(
                    KvsARN=kvs_arn,
                    Key=f'revoked:{jti}',
                    Value=str(int(time.time())),
                    IfMatch='*'
                )
                logger.info(f'Session revoked in KVS: revoked:{jti}')
            except Exception as e:
                logger.error(f'Failed to write KVS revocation: {e}')

    # Build Entra logout redirect URL
    tenant_id = config.get('azure_tenant_id', '')
    post_logout_redirect = '/'
    if cookie_domain:
        post_logout_redirect = f'https://{cookie_domain.lstrip(".")}/'

    entra_logout_url = (
        f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/logout'
        f'?post_logout_redirect_uri={urllib.parse.quote(post_logout_redirect)}'
    )

    logger.info(f'Logout complete for jti={jti}, redirecting to Entra /logout')

    return {
        'statusCode': 302,
        'headers': {
            'Location': entra_logout_url,
            'Cache-Control': 'no-store',
        },
        'multiValueHeaders': {
            'Set-Cookie': [clear_auth_cookie, clear_azure_cookie],
        },
    }
