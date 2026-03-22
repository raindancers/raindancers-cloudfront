import json
import urllib.parse
import urllib.request
from jwt import PyJWK
import jwt
import boto3
import logging
import hmac
import hashlib
import base64
import time
import uuid
from datetime import datetime
from config_generated import get_config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = None
CONFIG = None
HMAC_SECRET = None


def get_config_cached():
    global CONFIG, dynamodb
    if CONFIG is None:
        CONFIG = get_config()
        dynamodb_region = CONFIG.get('dynamodb_region', 'us-east-1')
        dynamodb = boto3.client('dynamodb', region_name=dynamodb_region)
    return CONFIG


def get_hmac_secret():
    global HMAC_SECRET
    if HMAC_SECRET is not None:
        return HMAC_SECRET
    config = get_config_cached()
    HMAC_SECRET = config.get('hmac_key')
    if not HMAC_SECRET:
        raise ValueError('hmac_key not found in config')
    return HMAC_SECRET


def exchange_code_for_token(code, cognito_domain, client_id, redirect_uri, code_verifier):
    token_url = f'https://{cognito_domain}/oauth2/token'
    data = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'code': code,
        'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,
    }
    req = urllib.request.Request(
        token_url,
        data=urllib.parse.urlencode(data).encode('utf-8'),
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        logger.error(f'Token exchange HTTP error: {e.code} {e.read().decode()}')
        raise


def validate_jwt_token(id_token, client_id, user_pool_id, cognito_region):
    jwks_url = f'https://cognito-idp.{cognito_region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'
    with urllib.request.urlopen(jwks_url) as response:
        jwks = json.loads(response.read().decode('utf-8'))

    unverified_header = jwt.get_unverified_header(id_token)
    rsa_key = next((k for k in jwks['keys'] if k['kid'] == unverified_header['kid']), None)
    if not rsa_key:
        raise ValueError('Unable to find matching key')

    jwk = PyJWK.from_dict(rsa_key)
    issuer = f'https://cognito-idp.{cognito_region}.amazonaws.com/{user_pool_id}'
    return jwt.decode(id_token, jwk.key, algorithms=['RS256'], audience=client_id, issuer=issuer)


def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']

    try:
        config = get_config_cached()
        cognito_domain = config['cognito_domain']
        client_id = config['cognito_client_id']
        user_pool_id = config['cognito_user_pool_id']
        cognito_region = config['cognito_region']
        redirect_uri = config['redirect_uri']
        table_name = config.get('dynamodb_table_name')
        auto_revoke_on_reuse = config.get('auto_revoke_on_reuse', 'false').lower() == 'true'
        jwt_claims_whitelist_str = config.get('jwt_claims_whitelist', '')
    except Exception as e:
        logger.error(f'Config load failed: {e}')
        return {'status': '500', 'statusDescription': 'Internal Server Error', 'body': 'Configuration error'}

    params = urllib.parse.parse_qs(request.get('querystring', ''))
    code = params.get('code', [None])[0]
    state = params.get('state', [None])[0]

    if not code:
        return {'status': '400', 'statusDescription': 'Bad Request', 'body': 'Missing authorization code'}

    cookies = {}
    for cookie in (request.get('headers', {}).get('cookie') or [{}])[0].get('value', '').split('; '):
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            cookies[name] = value

    code_verifier = cookies.get('code_verifier')
    if not code_verifier:
        return {'status': '400', 'statusDescription': 'Bad Request', 'body': 'Authentication failed'}

    stored_state = cookies.get('oauth_state')
    if not stored_state or stored_state != state:
        return {'status': '400', 'statusDescription': 'Bad Request', 'body': 'Invalid state parameter'}

    if table_name and state:
        try:
            resp = dynamodb.get_item(
                TableName=table_name,
                Key={'pk': {'S': f'STATE#{state}'}, 'sk': {'S': f'STATE#{state}'}},
            )
            if not resp.get('Item'):
                dynamodb.put_item(TableName=table_name, Item={
                    'pk': {'S': f'STATE#{state}'}, 'sk': {'S': f'STATE#{state}'},
                    'used': {'BOOL': True},
                    'createdAt': {'N': str(int(time.time()))},
                    'expiresAt': {'N': str(int(time.time()) + 600)},
                })
            elif resp['Item'].get('used', {}).get('BOOL') and auto_revoke_on_reuse:
                return {'status': '400', 'statusDescription': 'Bad Request', 'body': 'Invalid or reused state token'}
        except Exception as e:
            logger.error(f'DynamoDB state check error: {e}')

    redirect_path = '/'
    try:
        padded = state + '=' * (4 - len(state) % 4)
        state_obj = json.loads(base64.urlsafe_b64decode(padded.replace('-', '+').replace('_', '/')))
        redirect_path = state_obj.get('p', '/')
    except Exception:
        pass

    try:
        token_response = exchange_code_for_token(code, cognito_domain, client_id, redirect_uri, code_verifier)
        id_token = token_response['id_token']

        payload = validate_jwt_token(id_token, client_id, user_pool_id, cognito_region)
        logger.info(f'JWT validated for: {payload.get("email", payload.get("cognito:username", "unknown"))}')

        jti = f'sess_{uuid.uuid4().hex}'
        user_id = payload.get('sub') or payload.get('email') or payload.get('cognito:username')

        if jwt_claims_whitelist_str:
            whitelist = json.loads(jwt_claims_whitelist_str)
            filtered_payload = {k: v for k, v in payload.items() if k in whitelist}
        else:
            filtered_payload = {k: v for k, v in payload.items() if not k.startswith('cognito:')}

        session_payload = {
            **filtered_payload,
            'jti': jti,
            'exp': payload.get('exp', int(time.time()) + 3600),
            'iat': int(time.time()),
            'iss': redirect_uri,
            'idp': payload.get('iss'),
        }

        if table_name and user_id:
            try:
                dynamodb.put_item(TableName=table_name, Item={
                    'pk': {'S': f'SESSION#{user_id}'}, 'sk': {'S': f'SESSION#{jti}'},
                    'gsi1pk': {'S': f'USER#{user_id}'}, 'gsi1sk': {'S': f'SESSION#{int(time.time())}'},
                    'jti': {'S': jti}, 'userId': {'S': user_id},
                    'email': {'S': payload.get('email', '')},
                    'createdAt': {'N': str(int(time.time()))},
                    'revoked': {'BOOL': False},
                    'expiresAt': {'N': str(int(time.time()) + 3600)},
                })
            except Exception as e:
                logger.error(f'Failed to store session: {e}')

        header_b64 = base64.urlsafe_b64encode(
            json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(session_payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        signing_input = f'{header_b64}.{payload_b64}'
        hmac_secret = get_hmac_secret()
        sig = hmac.new(hmac_secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        cookie_value = f'{signing_input}.{base64.urlsafe_b64encode(sig).decode().rstrip("=")}'

        exp_ts = payload.get('exp', int(time.time()) + 3600)
        expires_str = datetime.utcfromtimestamp(exp_ts).strftime('%a, %d %b %Y %H:%M:%S GMT')

        return {
            'status': '302',
            'statusDescription': 'Found',
            'headers': {
                'location': [{'key': 'Location', 'value': redirect_path}],
                'set-cookie': [
                    {'key': 'Set-Cookie', 'value': f'__Host-auth_session={cookie_value}; HttpOnly; Secure; SameSite=Lax; Path=/; Expires={expires_str}'},
                    {'key': 'Set-Cookie', 'value': 'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'},
                    {'key': 'Set-Cookie', 'value': 'code_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'},
                ],
                'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}],
            },
        }

    except Exception as e:
        import traceback
        logger.error(f'OAuth callback error: {traceback.format_exc()}')
        return {'status': '500', 'statusDescription': 'Internal Server Error', 'body': 'Authentication failed'}
