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
from datetime import datetime, timedelta
from config_generated import get_config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Log boto3 version for diagnostics
logger.info(f'boto3 version: {boto3.__version__}')

# Initialize AWS clients
sts_client = boto3.client('sts', region_name='us-east-1')
# DynamoDB and SNS clients will be initialized lazily with region from config.
# Set to None here for lazy initialization - they'll be created on first use with the
# correct region from Secrets Manager, enabling cross-region Lambda@Edge deployments.
dynamodb = None
sns_client = None

# Cache HMAC secret and config (Lambda@Edge reuses execution context)
HMAC_SECRET = None
CONFIG = None

def get_config_cached():
    """Get cached config"""
    global CONFIG, dynamodb, sns_client
    if CONFIG is None:
        CONFIG = get_config()
        # Initialize DynamoDB and SNS clients with region from config
        dynamodb_region = CONFIG.get('dynamodb_region', 'us-east-1')
        dynamodb = boto3.client('dynamodb', region_name=dynamodb_region)
        sns_client = boto3.client('sns', region_name=dynamodb_region)
        logger.info(f'DynamoDB and SNS clients initialized for region: {dynamodb_region}')
    return CONFIG

def get_hmac_secret():
    """Get HMAC secret from config"""
    global HMAC_SECRET
    if HMAC_SECRET is not None:
        return HMAC_SECRET
    
    config = get_config_cached()
    HMAC_SECRET = config.get('hmac_key')
    if not HMAC_SECRET:
        raise ValueError('hmac_key not found in config')
    
    logger.info('HMAC secret loaded from config')
    return HMAC_SECRET

def get_federated_token(sts_audience):
    """Generate JWT from AWS STS for Azure AD federated authentication"""
    logger.info(f'Getting federated token for audience: {sts_audience}')
    try:
        response = sts_client._make_api_call(
            'GetWebIdentityToken',
            {
                'Audience': [sts_audience],
                'DurationSeconds': 900,
                'SigningAlgorithm': 'RS256'
            }
        )
        logger.info('Successfully obtained federated token from STS')
        return response['WebIdentityToken']
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f'Failed to get web identity token')
        logger.error(f'Error type: {type(e).__name__}')
        logger.error(f'Error message: {str(e)}')
        logger.error(f'Full traceback: {error_details}')
        logger.error(f'boto3 version: {boto3.__version__}')
        logger.error(f'Requirements: boto3 >= 1.35.36, Outbound Identity Federation enabled')
        raise

def exchange_code_for_token(code, azure_tenant_id, azure_client_id, redirect_uri, sts_audience, code_verifier):
    """Exchange authorization code for JWT token using federated identity with PKCE"""
    logger.info(f'Starting token exchange with Azure AD (PKCE enabled)')
    logger.info(f'Tenant ID: {azure_tenant_id}, Client ID: {azure_client_id}')
    token_url = f'https://login.microsoftonline.com/{azure_tenant_id}/oauth2/v2.0/token'
    
    # Use federated identity - no client secret needed
    # Lambda role has federated credential configured in Azure AD
    logger.info('Getting federated token for client assertion')
    client_assertion = get_federated_token(sts_audience)
    logger.info(f'Client assertion obtained, length: {len(client_assertion)}')
    
    # DEBUG: decode and log JWT header+payload (no signature)
    try:
        import base64 as _b64, json as _json
        _parts = client_assertion.split('.')
        _header = _json.loads(_b64.urlsafe_b64decode(_parts[0] + '=='))
        _payload_raw = _parts[1] + '=='
        _payload = _json.loads(_b64.urlsafe_b64decode(_payload_raw))
        logger.info(f'DEBUG client_assertion header: {_json.dumps(_header)}')
        logger.info(f'DEBUG client_assertion payload: {_json.dumps(_payload)}')
    except Exception as _e:
        logger.warning(f'DEBUG decode failed: {_e}')
    
    data = {
        'grant_type': 'authorization_code',
        'client_id': azure_client_id,
        'code': code,
        'redirect_uri': redirect_uri,
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': client_assertion,
        'code_verifier': code_verifier
    }
    
    logger.info(f'Making token request to: {token_url}')
    req = urllib.request.Request(
        token_url,
        data=urllib.parse.urlencode(data).encode('utf-8'),
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            logger.info(f'Token exchange response status: {response.status}')
            token_response = json.loads(response.read().decode('utf-8'))
            logger.info(f'Token response keys: {list(token_response.keys())}')
            return token_response
    except urllib.error.HTTPError as e:
        logger.error(f'HTTP error during token exchange: {e.code} {e.reason}')
        error_body = e.read().decode('utf-8')
        logger.error(f'Error response body: {error_body}')
        raise
    except Exception as e:
        logger.error(f'Unexpected error during token exchange: {type(e).__name__}: {str(e)}')
        raise

def validate_jwt_token(id_token, azure_tenant_id, azure_client_id):
    """Validate JWT token from Azure AD"""
    logger.info('Starting JWT token validation')
    # Get Azure AD public keys
    jwks_url = f'https://login.microsoftonline.com/{azure_tenant_id}/discovery/v2.0/keys'
    logger.info(f'Fetching JWKS from: {jwks_url}')
    
    with urllib.request.urlopen(jwks_url) as response:
        jwks = json.loads(response.read().decode('utf-8'))
    logger.info(f'Retrieved {len(jwks.get("keys", []))} keys from JWKS')
    
    # Decode and validate
    unverified_header = jwt.get_unverified_header(id_token)
    logger.info(f'Token header kid: {unverified_header.get("kid")}')
    rsa_key = None
    
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = key
            logger.info(f'Found matching key for kid: {key["kid"]}')
            break
    
    if not rsa_key:
        logger.error(f'Unable to find key for kid: {unverified_header.get("kid")}')
        raise ValueError('Unable to find appropriate key')
    
    # Convert JWK to key object
    logger.info('Converting JWK to key object')
    jwk = PyJWK.from_dict(rsa_key)
    
    # Validate token
    logger.info('Validating JWT signature and claims')
    payload = jwt.decode(
        id_token,
        jwk.key,
        algorithms=['RS256'],
        audience=azure_client_id,
        issuer=f'https://login.microsoftonline.com/{azure_tenant_id}/v2.0'
    )
    logger.info(f'JWT validation successful, user: {payload.get("email", payload.get("preferred_username", "unknown"))}')
    
    return payload



def lambda_handler(event, context):
    """Handle OAuth callback from Azure AD"""
    request = event['Records'][0]['cf']['request']
    
    # Debug logging for cookies
    logger.info(f'Request headers: {json.dumps(request.get("headers", {}))}')
    
    # Load configuration
    try:
        config = get_config_cached()
        azure_tenant_id = config['azure_tenant_id']
        azure_client_id = config['azure_client_id']
        redirect_uri = config['redirect_uri']
        sts_audience = config.get('sts_audience', 'sts.amazonaws.com')
        table_name = config.get('dynamodb_table_name')
        security_alerts_topic_arn = config.get('security_alerts_topic_arn')
        auto_revoke_on_reuse = config.get('auto_revoke_on_reuse', 'false').lower() == 'true'
        allowed_domains_str = config.get('allowed_domains', '[]')
        cookie_domain = config.get('cookie_domain', '')
        allowed_domains = json.loads(allowed_domains_str)
    except Exception as e:
        logger.error(f'Failed to load configuration: {str(e)}')
        return {
            'status': '500',
            'statusDescription': 'Internal Server Error',
            'body': 'Configuration error'
        }
    
    # Validate Host header
    host_header = None
    if 'host' in request.get('headers', {}):
        host_header = request['headers']['host'][0]['value']
    
    if host_header and allowed_domains:
        if host_header not in allowed_domains:
            logger.error(f'Host header validation failed: {host_header} not in allowed domains')
            return {
                'status': '400',
                'statusDescription': 'Bad Request',
                'body': 'Invalid request'
            }
    
    # Parse query string
    query_string = request.get('querystring', '')
    params = urllib.parse.parse_qs(query_string)
    
    # Extract code and state
    code = params.get('code', [None])[0]
    state = params.get('state', [None])[0]
    
    logger.info(f'OAuth callback - code present: {code is not None}, state: {state}')
    
    if not code:
        return {
            'status': '400',
            'statusDescription': 'Bad Request',
            'body': 'Missing authorization code'
        }
    
    # Validate CSRF state
    cookies = {}
    if 'cookie' in request.get('headers', {}):
        cookie_header = request['headers']['cookie'][0]['value']
        logger.info(f'Cookie header: {cookie_header}')
        for cookie in cookie_header.split('; '):
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                cookies[name] = value
    else:
        logger.warning('No cookie header in request')
    
    logger.info(f'Parsed cookies: {list(cookies.keys())}')
    
    # Get code_verifier from cookie for PKCE
    code_verifier = cookies.get('code_verifier')
    if not code_verifier:
        logger.error('PKCE code_verifier missing from cookies')
        return {
            'status': '400',
            'statusDescription': 'Bad Request',
            'body': 'Authentication failed'
        }
    
    logger.info('PKCE code_verifier retrieved from cookie')
    
    stored_state = cookies.get('oauth_state')
    if not stored_state or stored_state != state:
        logger.error(f'CSRF validation failed: stored={stored_state}, received={state}')
        return {
            'status': '400',
            'statusDescription': 'Bad Request',
            'body': 'Invalid state parameter'
        }
    
    # Validate state token in DynamoDB (one-time-use enforcement)
    if table_name:
        try:
            response = dynamodb.get_item(
                TableName=table_name,
                Key={'pk': {'S': f'STATE#{state}'}, 'sk': {'S': f'STATE#{state}'}}
            )
            
            item = response.get('Item')
            
            if not item:
                # First use - store in DynamoDB
                dynamodb.put_item(
                    TableName=table_name,
                    Item={
                        'pk': {'S': f'STATE#{state}'},
                        'sk': {'S': f'STATE#{state}'},
                        'used': {'BOOL': True},
                        'createdAt': {'N': str(int(time.time()))},
                        'expiresAt': {'N': str(int(time.time()) + 600)}
                    }
                )
            elif item.get('used', {}).get('BOOL'):
                # Token reuse detected - security incident
                logger.error(f'State token reuse detected: {state}')
                
                if security_alerts_topic_arn:
                    try:
                        sns_client.publish(
                            TopicArn=security_alerts_topic_arn,
                            Subject='Security Alert: State Token Reuse Detected',
                            Message=json.dumps({
                                'event': 'STATE_TOKEN_REUSE',
                                'state': state,
                                'timestamp': int(time.time()),
                                'ip': request.get('clientIp', 'unknown')
                            })
                        )
                    except Exception as e:
                        logger.error(f'Failed to publish security alert: {e}')
                
                return {
                    'status': '400',
                    'statusDescription': 'Bad Request',
                    'body': 'Invalid or reused state token'
                }
        except Exception as e:
            logger.error(f'DynamoDB state validation error: {e}')
    
    logger.info(f'CSRF validation passed, proceeding with token exchange')
    
    # Decode state to get original path
    redirect_path = '/'
    try:
        # Decode base64url state
        state_padded = state + '=' * (4 - len(state) % 4)
        state_decoded = base64.urlsafe_b64decode(state_padded.replace('-', '+').replace('_', '/')).decode('utf-8')
        state_obj = json.loads(state_decoded)
        redirect_path = state_obj.get('p', '/')
        logger.info(f'Decoded original path from state: {redirect_path}')
    except Exception as e:
        logger.warning(f'Could not decode state, using default redirect: {str(e)}')
        redirect_path = '/'
    
    try:
        # Exchange code for tokens
        logger.info('Step 1: Exchanging authorization code for tokens (with PKCE)')
        token_response = exchange_code_for_token(code, azure_tenant_id, azure_client_id, redirect_uri, sts_audience, code_verifier)
        id_token = token_response['id_token']
        logger.info('Step 1 complete: Received id_token from Azure')
        
        # Validate JWT
        logger.info('Step 2: Validating JWT token')
        payload = validate_jwt_token(id_token, azure_tenant_id, azure_client_id)
        logger.info('Step 2 complete: JWT token validated successfully')
        
        # Store Azure AD JWT reference for IAM authorization
        azure_id_token = id_token
        logger.info('Azure AD JWT will be stored for IAM authorization')
        
        # Validate nonce in DynamoDB (one-time-use enforcement)
        token_nonce = payload.get('nonce')
        if table_name and token_nonce:
            try:
                response = dynamodb.get_item(
                    TableName=table_name,
                    Key={'pk': {'S': f'NONCE#{token_nonce}'}, 'sk': {'S': f'NONCE#{token_nonce}'}}
                )
                
                item = response.get('Item')
                
                if not item:
                    # First use - store in DynamoDB
                    dynamodb.put_item(
                        TableName=table_name,
                        Item={
                            'pk': {'S': f'NONCE#{token_nonce}'},
                            'sk': {'S': f'NONCE#{token_nonce}'},
                            'used': {'BOOL': True},
                            'createdAt': {'N': str(int(time.time()))},
                            'expiresAt': {'N': str(int(time.time()) + 600)}
                        }
                    )
                elif item.get('used', {}).get('BOOL'):
                    # Nonce reuse detected - security incident
                    logger.error(f'Nonce reuse detected: {token_nonce}')
                    
                    if security_alerts_topic_arn:
                        try:
                            sns_client.publish(
                                TopicArn=security_alerts_topic_arn,
                                Subject='Security Alert: Nonce Reuse Detected',
                                Message=json.dumps({
                                    'event': 'NONCE_REUSE',
                                    'nonce': token_nonce,
                                    'timestamp': int(time.time()),
                                    'ip': request.get('clientIp', 'unknown')
                                })
                            )
                        except Exception as e:
                            logger.error(f'Failed to publish security alert: {e}')
                    
                    return {
                        'status': '400',
                        'statusDescription': 'Bad Request',
                        'body': 'Invalid or reused nonce'
                    }
            except Exception as e:
                logger.error(f'DynamoDB nonce validation error: {e}')
        
        # Create HMAC-signed session JWT
        logger.info('Step 3: Creating HMAC-signed session JWT')
        
        # Generate unique session ID (jti)
        jti = f"sess_{uuid.uuid4().hex}"
        user_id = payload.get('sub') or payload.get('email') or payload.get('preferred_username')
        
        header = {"alg": "HS256", "typ": "JWT"}
        
        # Filter claims based on whitelist
        jwt_claims_whitelist_str = config.get('jwt_claims_whitelist', '')
        if jwt_claims_whitelist_str:
            whitelist = json.loads(jwt_claims_whitelist_str)
            filtered_payload = {k: v for k, v in payload.items() if k in whitelist}
            logger.info(f'Applied claims whitelist: {whitelist}')
        else:
            # Fallback: filter out Microsoft internal claims only (should not reach here with proper config)
            logger.warning('No JWT claims whitelist configured, using fallback filter')
            filtered_payload = {k: v for k, v in payload.items() if k not in ['aio', 'rh', 'uti']}
        
        # Include filtered Azure AD claims in session JWT
        azure_exp = payload.get('exp', int(time.time()) + 3600)
        session_payload = {
            **filtered_payload,
            "jti": jti,
            "exp": azure_exp,  # Match Azure AD expiration
            "iat": int(time.time()),
            "iss": redirect_uri,
            "idp": payload.get("iss")
        }
        
        # Store session in DynamoDB
        if table_name and user_id:
            try:
                dynamodb.put_item(
                    TableName=table_name,
                    Item={
                        'pk': {'S': f'SESSION#{user_id}'},
                        'sk': {'S': f'SESSION#{jti}'},
                        'gsi1pk': {'S': f'USER#{user_id}'},
                        'gsi1sk': {'S': f'SESSION#{int(time.time())}'},
                        'jti': {'S': jti},
                        'userId': {'S': user_id},
                        'email': {'S': payload.get('email', '')},
                        'createdAt': {'N': str(int(time.time()))},
                        'revoked': {'BOOL': False},
                        'expiresAt': {'N': str(int(time.time()) + 3600)}
                    }
                )
                logger.info(f'Session stored in DynamoDB: {jti}')
            except Exception as e:
                logger.error(f'Failed to store session in DynamoDB: {e}')
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(session_payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        signing_input = f"{header_b64}.{payload_b64}"
        hmac_secret = get_hmac_secret()
        signature = hmac.new(
            hmac_secret.encode('utf-8'),
            signing_input.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        cookie_value = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        logger.info('Step 3 complete: HMAC-signed JWT created')
        
        # Calculate expiry from Azure AD token
        azure_exp_timestamp = payload.get('exp', int(time.time()) + 3600)
        expires = datetime.utcfromtimestamp(azure_exp_timestamp)
        expires_str = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')
        logger.info(f'Cookie expiry set to: {expires_str}')
        
        # Build Set-Cookie headers
        domain_attr = f'; Domain={cookie_domain}' if cookie_domain else ''
        cookie_prefix = '__Secure-' if cookie_domain else '__Host-'
        auth_cookie = (
            f'{cookie_prefix}auth_session={cookie_value}; '
            f'HttpOnly; Secure; SameSite=Lax; '
            f'Path=/; '
            f'Expires={expires_str}'
            f'{domain_attr}'
        )
        
        # Create Azure AD JWT cookie for IAM authorization
        azure_cookie = (
            f'{cookie_prefix}azure_token={azure_id_token}; '
            f'HttpOnly; Secure; SameSite=Lax; '
            f'Path=/; '
            f'Expires={expires_str}'
            f'{domain_attr}'
        )
        
        # Clear oauth_state cookie
        state_cookie = f'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0{domain_attr}'
        
        # Clear code_verifier cookie
        verifier_cookie = f'code_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0{domain_attr}'
        
        logger.info('Step 4: Building redirect response')
        response = {
            'status': '302',
            'statusDescription': 'Found',
            'headers': {
                'location': [{'key': 'Location', 'value': redirect_path}],
                'set-cookie': [
                    {'key': 'Set-Cookie', 'value': auth_cookie},
                    {'key': 'Set-Cookie', 'value': azure_cookie},
                    {'key': 'Set-Cookie', 'value': state_cookie},
                    {'key': 'Set-Cookie', 'value': verifier_cookie}
                ],
                'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}]
            }
        }
        logger.info(f'OAuth callback completed successfully, redirecting to {redirect_path}')
        return response
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f'Error during OAuth callback: {type(e).__name__}: {str(e)}')
        logger.error(f'Full traceback: {error_details}')
        return {
            'status': '500',
            'statusDescription': 'Internal Server Error',
            'body': 'Authentication failed'
        }
