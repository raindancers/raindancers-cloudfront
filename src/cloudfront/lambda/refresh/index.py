"""Refresh Lambda — silently renews expired sessions using stored Entra refresh tokens.

Handles GET /oauth2/refresh?return_to={url}. Extracts the session ID (jti) from the
expired-but-HMAC-valid session cookie, retrieves the stored refresh token from DynamoDB,
exchanges it with Entra's /token endpoint, issues a new HMAC-signed session JWT, and
redirects back to the original URL with a fresh session cookie.

If the refresh token is expired/revoked or unavailable, redirects to Entra login.
"""

import json
import urllib.parse
import urllib.request
import boto3
import logging
import hmac
import hashlib
import base64
import time
import uuid
from config_generated import get_config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Lazy-initialised clients (region from config)
dynamodb = None
sts_client = boto3.client('sts', region_name='us-east-1')
CONFIG = None


def get_config_cached():
    """Load and cache configuration from Secrets Manager."""
    global CONFIG, dynamodb
    if CONFIG is None:
        CONFIG = get_config()
        dynamodb_region = CONFIG.get('dynamodb_region', 'us-east-1')
        dynamodb = boto3.client('dynamodb', region_name=dynamodb_region)
        logger.info(f'DynamoDB client initialised for region: {dynamodb_region}')
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

    Verifies the signature but does NOT check exp — the token is expected to be expired
    (that's why we're refreshing). We only need to trust the jti claim.

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


def get_federated_token(sts_audience):
    """Generate JWT from AWS STS for Azure AD federated authentication."""
    try:
        response = sts_client._make_api_call(
            'GetWebIdentityToken',
            {
                'Audience': [sts_audience],
                'DurationSeconds': 900,
                'SigningAlgorithm': 'RS256'
            }
        )
        return response['WebIdentityToken']
    except Exception as e:
        logger.error(f'Failed to get federated token: {e}')
        raise


def exchange_refresh_token(refresh_token, tenant_id, client_id, sts_audience):
    """Exchange a refresh token for new tokens via Entra's /token endpoint.

    Args:
        refresh_token: The stored Entra refresh token.
        tenant_id: Entra tenant GUID.
        client_id: App registration client ID.
        sts_audience: STS audience for federated credential.

    Returns:
        Token response dict with id_token, access_token, refresh_token.

    Raises:
        urllib.error.HTTPError: If Entra returns an error.
    """
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    client_assertion = get_federated_token(sts_audience)

    data = {
        'grant_type': 'refresh_token',
        'client_id': client_id,
        'refresh_token': refresh_token,
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': client_assertion,
    }

    req = urllib.request.Request(
        token_url,
        data=urllib.parse.urlencode(data).encode('utf-8'),
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode('utf-8'))


def issue_session_jwt(payload_claims, secret):
    """Issue a new HMAC-SHA256 signed session JWT.

    Args:
        payload_claims: Dict of claims to include in the JWT payload.
        secret: The HMAC signing secret.

    Returns:
        The signed JWT string (header.payload.signature).
    """
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = base64url_encode(json.dumps(payload_claims, separators=(',', ':')).encode())

    signing_input = f'{header_b64}.{payload_b64}'
    signature = hmac.new(
        secret.encode('utf-8'),
        signing_input.encode('utf-8'),
        hashlib.sha256
    ).digest()
    signature_b64 = base64url_encode(signature)

    return f'{header_b64}.{payload_b64}.{signature_b64}'


def build_login_redirect(config):
    """Build redirect URL to Entra login (when refresh fails)."""
    tenant_id = config['azure_tenant_id']
    client_id = config['azure_client_id']
    redirect_uri = config['redirect_uri']
    return (
        f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize'
        f'?client_id={urllib.parse.quote(client_id)}'
        f'&redirect_uri={urllib.parse.quote(redirect_uri)}'
        f'&response_type=code'
        f'&scope={urllib.parse.quote("openid profile email")}'
    )


def lambda_handler(event, context):
    """Handle refresh requests: GET /oauth2/refresh?return_to={url}."""
    # Support both Function URL and Lambda@Edge event formats
    if 'Records' in event:
        # Lambda@Edge format
        request = event['Records'][0]['cf']['request']
        query_string = request.get('querystring', '')
        cookies_raw = request.get('headers', {}).get('cookie', [{}])
        cookie_header = cookies_raw[0].get('value', '') if cookies_raw else ''
    else:
        # Function URL format
        query_string = event.get('rawQueryString', '')
        cookie_header = event.get('cookies', [])
        if isinstance(cookie_header, list):
            cookie_header = '; '.join(cookie_header)
        else:
            cookie_header = event.get('headers', {}).get('cookie', '')

    config = get_config_cached()
    cookie_domain = config.get('cookie_domain', '')

    # Parse return_to from query string
    params = urllib.parse.parse_qs(query_string)
    return_to = params.get('return_to', ['/'])[0]

    # Sanitise return_to: only allow same-domain or relative paths
    if return_to.startswith('http'):
        allowed_domains = json.loads(config.get('allowed_domains', '[]'))
        parsed = urllib.parse.urlparse(return_to)
        if parsed.hostname and parsed.hostname not in allowed_domains:
            logger.warning(f'Open redirect blocked: {return_to}')
            return_to = '/'

    # Parse session cookie
    cookies = {}
    for cookie in cookie_header.split('; '):
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()

    session_token = cookies.get('__Secure-auth_session') or cookies.get('__Host-auth_session')
    if not session_token:
        logger.warning('No session cookie found in refresh request')
        return redirect_response(build_login_redirect(config), cookie_domain)

    # Verify HMAC signature (don't check exp — it's expected to be expired)
    hmac_secret = get_hmac_secret()
    payload = verify_hmac_jwt(session_token, hmac_secret)
    if not payload:
        logger.warning('Invalid HMAC signature on session cookie during refresh')
        return redirect_response(build_login_redirect(config), cookie_domain, clear_session=True)

    jti = payload.get('jti')
    if not jti:
        logger.warning('No jti in session JWT — cannot look up refresh token')
        return redirect_response(build_login_redirect(config), cookie_domain, clear_session=True)

    # Retrieve refresh token from DynamoDB
    table_name = config.get('dynamodb_table_name')
    try:
        response = dynamodb.get_item(
            TableName=table_name,
            Key={'pk': {'S': f'REFRESH#{jti}'}, 'sk': {'S': f'REFRESH#{jti}'}}
        )
        item = response.get('Item')
        if not item:
            logger.warning(f'Refresh token not found for jti: {jti}')
            return redirect_response(build_login_redirect(config), cookie_domain, clear_session=True)

        stored_refresh_token = item['refresh_token']['S']
    except Exception as e:
        logger.error(f'DynamoDB error retrieving refresh token: {e}')
        return error_response(503, 'Service temporarily unavailable')

    # Exchange refresh token with Entra
    try:
        token_response = exchange_refresh_token(
            stored_refresh_token,
            config['azure_tenant_id'],
            config['azure_client_id'],
            config.get('sts_audience', 'api://AzureADTokenExchange')
        )
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if hasattr(e, 'read') else ''
        logger.error(f'Entra refresh failed ({e.code}): {error_body}')
        # Refresh token is likely expired or revoked — redirect to login
        return redirect_response(build_login_redirect(config), cookie_domain, clear_session=True)
    except Exception as e:
        logger.error(f'Entra refresh exchange error: {e}')
        return error_response(503, 'Authentication service unavailable')

    # Issue new session JWT
    new_jti = f"sess_{uuid.uuid4().hex}"
    new_exp = token_response.get('expires_in', 3600) + int(time.time())

    # Preserve existing claims from old session, update jti/exp/iat
    new_payload = {**payload}
    new_payload['jti'] = new_jti
    new_payload['exp'] = new_exp
    new_payload['iat'] = int(time.time())

    new_session_jwt = issue_session_jwt(new_payload, hmac_secret)

    # Store new refresh token, delete old one
    new_refresh_token = token_response.get('refresh_token', stored_refresh_token)
    try:
        refresh_ttl = int(time.time()) + (30 * 24 * 60 * 60)  # 30 days
        dynamodb.put_item(
            TableName=table_name,
            Item={
                'pk': {'S': f'REFRESH#{new_jti}'},
                'sk': {'S': f'REFRESH#{new_jti}'},
                'refresh_token': {'S': new_refresh_token},
                'user_id': {'S': payload.get('sub', '')},
                'customer_id': {'S': payload.get('customer_id', '')},
                'createdAt': {'N': str(int(time.time()))},
                'expiresAt': {'N': str(refresh_ttl)}
            }
        )
        # Delete old refresh token record
        dynamodb.delete_item(
            TableName=table_name,
            Key={'pk': {'S': f'REFRESH#{jti}'}, 'sk': {'S': f'REFRESH#{jti}'}}
        )
        logger.info(f'Refresh token rotated: {jti} -> {new_jti}')
    except Exception as e:
        logger.error(f'DynamoDB error during refresh token rotation: {e}')
        # Continue anyway — session JWT is already issued

    # Update session record in DynamoDB
    user_id = payload.get('sub', '')
    try:
        dynamodb.put_item(
            TableName=table_name,
            Item={
                'pk': {'S': f'SESSION#{user_id}'},
                'sk': {'S': f'SESSION#{new_jti}'},
                'gsi1pk': {'S': f'USER#{user_id}'},
                'gsi1sk': {'S': f'SESSION#{int(time.time())}'},
                'jti': {'S': new_jti},
                'userId': {'S': user_id},
                'email': {'S': payload.get('email', '')},
                'createdAt': {'N': str(int(time.time()))},
                'revoked': {'BOOL': False},
                'expiresAt': {'N': str(new_exp)}
            }
        )
    except Exception as e:
        logger.error(f'DynamoDB error storing new session: {e}')

    # Build response with new session cookie
    from datetime import datetime
    expires = datetime.utcfromtimestamp(new_exp)
    expires_str = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')
    domain_attr = f'; Domain={cookie_domain}' if cookie_domain else ''
    cookie_prefix = '__Secure-' if cookie_domain else '__Host-'

    auth_cookie = (
        f'{cookie_prefix}auth_session={new_session_jwt}; '
        f'HttpOnly; Secure; SameSite=Lax; '
        f'Path=/; '
        f'Expires={expires_str}'
        f'{domain_attr}'
    )

    logger.info(f'Session refreshed successfully: {jti} -> {new_jti}, redirecting to {return_to}')
    return {
        'statusCode': 302,
        'headers': {
            'Location': return_to,
            'Set-Cookie': auth_cookie,
            'Cache-Control': 'no-store',
        }
    }


def redirect_response(location, cookie_domain, clear_session=False):
    """Build a redirect response, optionally clearing the session cookie.

    Args:
        location: The URL to redirect to.
        cookie_domain: Domain for the cookie (empty string for __Host- prefix).
        clear_session: Whether to clear the session cookie.

    Returns:
        Lambda response dict with 302 redirect.
    """
    headers = {
        'Location': location,
        'Cache-Control': 'no-store',
    }
    if clear_session:
        domain_attr = f'; Domain={cookie_domain}' if cookie_domain else ''
        cookie_prefix = '__Secure-' if cookie_domain else '__Host-'
        headers['Set-Cookie'] = (
            f'{cookie_prefix}auth_session=; '
            f'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
            f'{domain_attr}'
        )
    return {'statusCode': 302, 'headers': headers}


def error_response(status_code, message):
    """Build an error response.

    Args:
        status_code: HTTP status code.
        message: Error message body.

    Returns:
        Lambda response dict.
    """
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': 'text/plain', 'Cache-Control': 'no-store'},
        'body': message,
    }
