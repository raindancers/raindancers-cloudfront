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
import web_identity

# RS256 web-identity half: the KMS signing key's region, baked into the
# generated config by the construct. Older generated configs (feature off) do
# not define it; default to empty so boto3 uses the ambient region and the
# feature stays off (is_enabled checks the signing-key id, not this).
try:
    from config_generated import WEB_IDENTITY_KEY_REGION
except ImportError:
    WEB_IDENTITY_KEY_REGION = ''

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

# The AWS principal-tags claim key. Scope principal tags are encoded into this
# claim in the same `:k=v:` shape the Cognito resolver and the pre-token
# injector emit, so the edge / AssumeRole path reads one format across IdPs.
PRINCIPAL_TAGS_CLAIM = 'https://aws.amazon.com/tags/principal_tags/Claims'


def encode_principal_tags(tags):
    """Encode a {name: value} tag map into the `:k=v:k2=v2:` principal-tags
    claim string. Returns None for an empty/falsy map. Pure and deterministic."""
    if not tags:
        return None
    return ':' + ':'.join(f'{name}={val}' for name, val in tags.items()) + ':'


def assembled_token_len(header_b64, payload_b64):
    """Byte length of the assembled compact JWS: header + '.' + payload + '.' +
    a 43-byte base64url HS256 signature segment. Matches the Cognito mint's
    guard arithmetic exactly so the two mints refuse at the same ceiling."""
    return len(header_b64) + 1 + len(payload_b64) + 1 + 43


def scope_token_exceeds(header_b64, payload_b64, max_bytes):
    """True when the assembled token is over `max_bytes` (refuse, never truncate)."""
    return assembled_token_len(header_b64, payload_b64) > max_bytes


def _sigv4_sign_hook(url, body_bytes, region):
    """Return SigV4 Authorization headers for a POST of ``body_bytes`` to ``url``,
    signed for the Lambda Function URL service ('lambda') with the edge Lambda's
    ambient credentials. Used when the hook endpoint is an IAM-gated Function URL
    (post_auth_hook_sigv4), so an authority-minting resolver is never a public,
    unauthenticated endpoint. Returns a dict of headers to add to the request.

    Signing is done with botocore primitives (available in the Lambda runtime);
    the Function URL's own IAM auth validates the signature against the edge
    role, which the resolver's resource policy grants lambda:InvokeFunctionUrl.
    """
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    session = boto3.Session()
    creds = session.get_credentials()
    if creds is None:
        raise RuntimeError('no ambient credentials to SigV4-sign the post-auth hook')
    sign_region = region or session.region_name or 'us-east-1'
    aws_req = AWSRequest(
        method='POST',
        url=url,
        data=body_bytes,
        headers={'Content-Type': 'application/json'},
    )
    SigV4Auth(creds.get_frozen_credentials(), 'lambda', sign_region).add_auth(aws_req)
    return dict(aws_req.headers)


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



def _parse_request_cookies(request):
    """Parse the request's Cookie header into a {name: value} dict (edge event
    shape). Returns an empty dict when no cookie header is present."""
    cookies = {}
    hdrs = request.get('headers', {})
    if 'cookie' in hdrs:
        for part in hdrs['cookie'][0]['value'].split('; '):
            if '=' in part:
                name, value = part.split('=', 1)
                cookies[name] = value
    return cookies


def _requested_scope(request):
    """The scope the operator is switching to, from the query string
    (?scope=brand:acme | ?scope=estate). Returns None when absent/blank."""
    qs = request.get('querystring', '') or ''
    for pair in qs.split('&'):
        if pair.startswith('scope='):
            val = urllib.parse.unquote(pair[len('scope='):]).strip()
            return val or None
    return None


def _verify_session_cookie(cookies, cookie_prefix):
    """Verify the HMAC session cookie and return its decoded payload, or None.

    Reuses the mint's own HMAC secret + SHA-256 scheme. A missing cookie, a
    malformed token, or a signature mismatch all return None (the caller then
    fails closed with 401). This is NOT a fresh Entra login — it proves the
    caller already holds a valid session minted by the OAuth callback.
    """
    token = cookies.get(f'{cookie_prefix}auth_session') or cookies.get('auth_session')
    if not token or token.count('.') != 2:
        return None
    header_b64, payload_b64, sig_b64 = token.split('.')
    try:
        expected = hmac.new(
            get_hmac_secret().encode('utf-8'),
            f'{header_b64}.{payload_b64}'.encode('utf-8'),
            hashlib.sha256,
        ).digest()
        got = base64.urlsafe_b64decode(sig_b64 + '=' * (-len(sig_b64) % 4))
        if not hmac.compare_digest(expected, got):
            return None
        padded = payload_b64 + '=' * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
    except Exception as e:
        logger.warning(f'scope switch: session cookie verify failed: {e}')
        return None


def handle_scope_switch(request):
    """Re-mint the operator's tokens for a REQUESTED scope (#195 §5.7 switch).

    Preconditions: the operator already holds a valid session (from the OAuth
    callback) and the two-token web_identity feature is on. This route:
      1. verifies the existing HMAC session cookie (no Entra round-trip);
      2. reads the requested scope from the query string;
      3. re-runs the post-auth resolver hook with ``requested_scope`` set, so
         the resolver mints that scope's ui_permissions + principal-tags (it
         fails closed to empty authority when the caller does not hold it);
      4. re-mints the HS256 session + RS256 web_identity cookies for that scope;
      5. revokes the prior jti so the old-scope token cannot be replayed;
      6. returns 200 JSON with the new Set-Cookie headers.

    Fail-closed throughout: no session -> 401; no scope -> 400; feature off or
    hook failure -> the same closed responses the callback uses.
    """
    try:
        config = get_config_cached()
    except Exception as e:
        logger.error(f'scope switch: failed to load config: {e}')
        return {'status': '500', 'statusDescription': 'Internal Server Error', 'body': 'Configuration error'}

    if not web_identity.is_enabled(config):
        return {'status': '404', 'statusDescription': 'Not Found', 'body': 'Not found'}

    cookie_domain = config.get('cookie_domain', '')
    cookie_prefix = '__Secure-' if cookie_domain else '__Host-'
    cookies = _parse_request_cookies(request)

    session = _verify_session_cookie(cookies, cookie_prefix)
    if not session:
        return {'status': '401', 'statusDescription': 'Unauthorized',
                'body': json.dumps({'error': 'invalid_session'})}

    requested = _requested_scope(request)
    if not requested:
        return {'status': '400', 'statusDescription': 'Bad Request',
                'body': json.dumps({'error': 'missing_scope'})}

    sub = session.get('sub')
    username = session.get('preferred_username')
    hook_url = config.get('post_auth_hook_url')
    if not hook_url:
        # Without the resolver there is no per-scope authority to mint.
        logger.error('scope switch: no post_auth_hook_url configured')
        return {'status': '404', 'statusDescription': 'Not Found', 'body': 'Not found'}

    # Re-run the resolver hook for the REQUESTED scope. Identical call shape to
    # the callback's hook, plus `requested_scope` — the resolver honours it and
    # fails closed (empty authority) when the caller does not hold that scope.
    additional_claims = {}
    scope_principal_tags = {}
    hook_timeout = int(config.get('post_auth_hook_timeout', '3'))
    hook_sigv4 = str(config.get('post_auth_hook_sigv4', 'false')).lower() == 'true'
    try:
        hook_body = json.dumps({
            'sub': sub,
            'email': session.get('email'),
            'username': username,
            'requested_scope': requested,
            'claims': {k: v for k, v in session.items()
                       if k not in ['aio', 'rh', 'uti', 'nonce', 'jti', 'iat', 'exp']},
        }).encode('utf-8')
        hook_headers = {'Content-Type': 'application/json'}
        if hook_sigv4:
            hook_headers = _sigv4_sign_hook(
                hook_url, hook_body,
                config.get('post_auth_hook_region', WEB_IDENTITY_KEY_REGION),
            )
        hook_req = urllib.request.Request(hook_url, data=hook_body, headers=hook_headers, method='POST')
        with urllib.request.urlopen(hook_req, timeout=hook_timeout) as resp:
            hook_result = json.loads(resp.read().decode('utf-8'))
            additional_claims = hook_result.get('additional_claims', {})
            scope_principal_tags = hook_result.get('principal_tags', {})
    except Exception as e:
        logger.error(f'scope switch: resolver hook failed: {e}')
        return {'status': '503', 'statusDescription': 'Service Unavailable',
                'body': json.dumps({'error': 'scope_resolution_unavailable'})}

    # A resolver that returned no scope tag for the requested scope means the
    # caller does not hold it: refuse rather than mint an empty-authority token.
    if not scope_principal_tags:
        logger.warning(f'scope switch: caller {sub} does not hold scope {requested}')
        return {'status': '403', 'statusDescription': 'Forbidden',
                'body': json.dumps({'error': 'scope_not_held'})}

    # Build the new session payload — same shape and whitelist discipline as the
    # callback mint, carrying the resolver's new-scope claims + principal tags.
    jwt_claims_whitelist_str = config.get('jwt_claims_whitelist', '')
    whitelist = json.loads(jwt_claims_whitelist_str) if jwt_claims_whitelist_str else None
    base_claims = {k: v for k, v in session.items()
                   if k not in ['jti', 'iat', PRINCIPAL_TAGS_CLAIM]}
    if whitelist is not None:
        base_claims = {k: v for k, v in base_claims.items() if k in whitelist or k in ('sub', 'exp', 'iss', 'idp')}

    new_jti = f'sess_{uuid.uuid4().hex}'
    ttl_exp = int(session.get('exp', int(time.time()) + 3600))
    session_payload = {
        **base_claims,
        **additional_claims,
        'jti': new_jti,
        'iat': int(time.time()),
    }
    encoded_tags = encode_principal_tags(scope_principal_tags)
    if encoded_tags is not None:
        tag_allowed = (PRINCIPAL_TAGS_CLAIM in whitelist) if whitelist is not None else True
        if tag_allowed:
            session_payload[PRINCIPAL_TAGS_CLAIM] = encoded_tags

    header = {'alg': 'HS256', 'typ': 'JWT'}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(session_payload, separators=(',', ':')).encode()).decode().rstrip('=')

    scope_token_max_bytes = int(config.get('scope_token_max_bytes', '7168'))
    if scope_token_exceeds(header_b64, payload_b64, scope_token_max_bytes):
        logger.error(f'scope switch: assembled token over {scope_token_max_bytes} bytes; refusing')
        return {'status': '500', 'statusDescription': 'Internal Server Error',
                'body': json.dumps({'error': 'scope_exceeds_token_limit'})}

    signature = hmac.new(get_hmac_secret().encode('utf-8'),
                         f'{header_b64}.{payload_b64}'.encode('utf-8'), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    session_cookie_value = f'{header_b64}.{payload_b64}.{signature_b64}'

    # Re-mint the RS256 web_identity token for the new scope, SAME expiry + SAME
    # principal-tags value as the session cookie (one source, never disagree).
    wi_additional_claims = {}
    if additional_claims:
        wi_additional_claims = ({k: v for k, v in additional_claims.items() if k in whitelist}
                                if whitelist is not None else dict(additional_claims))
    try:
        wi_token = web_identity.mint_web_identity_token(
            config, WEB_IDENTITY_KEY_REGION,
            subject=sub,
            principal_tags_claim=PRINCIPAL_TAGS_CLAIM,
            principal_tags_value=session_payload.get(PRINCIPAL_TAGS_CLAIM),
            ttl_exp=ttl_exp,
            username=username,
            additional_claims=wi_additional_claims,
            max_bytes=scope_token_max_bytes,
        )
    except Exception as e:
        logger.error(f'scope switch: web_identity mint failed: {e}')
        return {'status': '500', 'statusDescription': 'Internal Server Error',
                'body': json.dumps({'error': 'remint_failed'})}

    # Revoke the PRIOR jti so the old-scope token cannot be replayed after switch.
    old_jti = session.get('jti')
    user_id = sub or session.get('email') or username
    table_name = config.get('dynamodb_table_name')
    if table_name and user_id and old_jti:
        try:
            dynamodb.update_item(
                TableName=table_name,
                Key={'pk': {'S': f'SESSION#{user_id}'}, 'sk': {'S': f'SESSION#{old_jti}'}},
                UpdateExpression='SET revoked = :t',
                ExpressionAttributeValues={':t': {'BOOL': True}},
            )
            logger.info(f'scope switch: revoked prior jti {old_jti}')
        except Exception as e:
            logger.error(f'scope switch: failed to revoke prior jti {old_jti}: {e}')
    # Record the new session so it is a first-class, revocable session.
    if table_name and user_id:
        try:
            dynamodb.put_item(TableName=table_name, Item={
                'pk': {'S': f'SESSION#{user_id}'}, 'sk': {'S': f'SESSION#{new_jti}'},
                'gsi1pk': {'S': f'USER#{user_id}'}, 'gsi1sk': {'S': f'SESSION#{int(time.time())}'},
                'jti': {'S': new_jti}, 'userId': {'S': user_id},
                'createdAt': {'N': str(int(time.time()))}, 'revoked': {'BOOL': False},
                'expiresAt': {'N': str(ttl_exp)},
            })
        except Exception as e:
            logger.error(f'scope switch: failed to store new session {new_jti}: {e}')

    expires_str = datetime.utcfromtimestamp(ttl_exp).strftime('%a, %d %b %Y %H:%M:%S GMT')
    domain_attr = f'; Domain={cookie_domain}' if cookie_domain else ''
    attrs = f'HttpOnly; Secure; SameSite=Lax; Path=/; Expires={expires_str}{domain_attr}'
    set_cookie_headers = [
        {'key': 'Set-Cookie', 'value': f'{cookie_prefix}auth_session={session_cookie_value}; {attrs}'},
        {'key': 'Set-Cookie', 'value': f'{cookie_prefix}web_identity={wi_token}; {attrs}'},
    ]
    return {
        'status': '200',
        'statusDescription': 'OK',
        'headers': {
            'content-type': [{'key': 'Content-Type', 'value': 'application/json'}],
            'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}],
            'set-cookie': set_cookie_headers,
        },
        'body': json.dumps({'scope': requested, 'jti': new_jti}),
    }


def lambda_handler(event, context):
    """Handle OAuth callback from Azure AD"""
    request = event['Records'][0]['cf']['request']

    # RS256 web-identity half: serve the JWKS (the asymmetric key's public half)
    # so STS can verify the role-assumption token. This route is independent of
    # the OAuth callback flow; handle it before anything else. Only active when
    # the feature is on (signing-key id present in config).
    uri = request.get('uri', '')
    if uri.endswith('/.well-known/jwks.json'):
        try:
            cfg = get_config_cached()
        except Exception as e:
            logger.error(f'JWKS: failed to load configuration: {e}')
            return {'status': '500', 'statusDescription': 'Internal Server Error', 'body': 'Configuration error'}
        if not web_identity.is_enabled(cfg):
            return {'status': '404', 'statusDescription': 'Not Found', 'body': 'Not found'}
        try:
            return web_identity.jwks_document(cfg, WEB_IDENTITY_KEY_REGION)
        except Exception as e:
            logger.error(f'JWKS: failed to build document: {e}')
            return {'status': '500', 'statusDescription': 'Internal Server Error', 'body': 'JWKS unavailable'}

    # OIDC discovery document — STS AssumeRoleWithWebIdentity discovers the
    # issuer's jwks_uri from here before validating the token. Served alongside
    # the JWKS; same feature gate.
    if uri.endswith('/.well-known/openid-configuration'):
        try:
            cfg = get_config_cached()
        except Exception as e:
            logger.error(f'OIDC discovery: failed to load configuration: {e}')
            return {'status': '500', 'statusDescription': 'Internal Server Error', 'body': 'Configuration error'}
        if not web_identity.is_enabled(cfg):
            return {'status': '404', 'statusDescription': 'Not Found', 'body': 'Not found'}
        try:
            return web_identity.openid_configuration_document(cfg)
        except Exception as e:
            logger.error(f'OIDC discovery: failed to build document: {e}')
            return {'status': '500', 'statusDescription': 'Internal Server Error', 'body': 'Discovery document unavailable'}

    # Scope SWITCH / re-mint (#195 §5.7). The operator is ALREADY authenticated
    # (they hold a valid session from the OAuth callback); switching brand/estate
    # must NOT re-run the Entra login. This route reuses the existing session,
    # re-runs the post-auth resolver hook for the REQUESTED scope, re-mints the
    # session + web_identity cookies for that scope, and revokes the prior jti.
    # It is independent of the callback flow and gated on the web_identity
    # feature (there is no scope to switch without the two-token model).
    if uri.endswith('/oauth2/switch'):
        return handle_scope_switch(request)

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
    
    # Validate Host header — accept the configured domains OR any subdomain of them.
    # This supports a single zone-level config (e.g. alpha.example.com) serving
    # multiple subdomains (payload./strapi./medusa.alpha.example.com) where the
    # auth cookie is shared across subdomains via cookieDomain.
    host_header = None
    if 'host' in request.get('headers', {}):
        host_header = request['headers']['host'][0]['value']

    if host_header and allowed_domains:
        host_allowed = any(
            host_header == d or host_header.endswith('.' + d)
            for d in allowed_domains
        )
        if not host_allowed:
            logger.error(f'Host header validation failed: {host_header} not in allowed domains')
            return {
                'status': '400',
                'statusDescription': 'Bad Request',
                'body': 'Invalid request'
            }

    # Rebuild redirect_uri from the actual (validated) request host so it matches
    # the reply address used in the authorization request. The config's redirect_uri
    # is zone-scoped, but the browser initiated login from the specific subdomain.
    if host_header:
        redirect_uri = f'https://{host_header}/oauth2/callback'
        logger.info(f'Using request-host redirect_uri: {redirect_uri}')
    
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
    
    # Decode state to get original path and host
    redirect_path = '/'
    try:
        # Decode base64url state
        state_padded = state + '=' * (4 - len(state) % 4)
        state_decoded = base64.urlsafe_b64decode(state_padded.replace('-', '+').replace('_', '/')).decode('utf-8')
        state_obj = json.loads(state_decoded)
        original_path = state_obj.get('p', '/')
        original_host = state_obj.get('h', '')
        if original_host:
            redirect_path = f'https://{original_host}{original_path}'
        else:
            redirect_path = original_path
        logger.info(f'Decoded redirect target from state: {redirect_path}')
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
        
        # Post-auth identity hook: call external endpoint to resolve application-specific claims
        # (e.g., Medusa customer_id). Only called when post_auth_hook_url is configured.
        additional_claims = {}
        scope_principal_tags = {}
        post_auth_hook_url = config.get('post_auth_hook_url')
        if post_auth_hook_url:
            logger.info(f'Step 2.5: Calling post-auth identity hook: {post_auth_hook_url}')
            hook_timeout = int(config.get('post_auth_hook_timeout', '3'))
            hook_fail_closed = config.get('post_auth_hook_fail_closed', 'true').lower() == 'true'
            hook_sigv4 = str(config.get('post_auth_hook_sigv4', 'false')).lower() == 'true'
            try:
                hook_body = json.dumps({
                    'sub': payload.get('sub'),
                    'email': payload.get('email'),
                    'claims': {k: v for k, v in payload.items() if k not in ['aio', 'rh', 'uti', 'nonce']}
                }).encode('utf-8')
                # When the hook is an IAM-gated Lambda Function URL (an
                # authority-minting resolver must NOT be a public endpoint),
                # SigV4-sign the request with the edge role's credentials so the
                # URL's AWS_IAM auth admits it. Default off: an ordinary identity
                # hook (e.g. customer_id resolution) stays an unsigned POST.
                hook_headers = {'Content-Type': 'application/json'}
                if hook_sigv4:
                    hook_headers = _sigv4_sign_hook(
                        post_auth_hook_url, hook_body,
                        config.get('post_auth_hook_region', WEB_IDENTITY_KEY_REGION),
                    )
                hook_req = urllib.request.Request(
                    post_auth_hook_url,
                    data=hook_body,
                    headers=hook_headers,
                    method='POST'
                )
                with urllib.request.urlopen(hook_req, timeout=hook_timeout) as hook_response:
                    hook_result = json.loads(hook_response.read().decode('utf-8'))
                    additional_claims = hook_result.get('additional_claims', {})
                    # Scope principal tags (R: AWS principal-tags for AssumeRole
                    # session tags). Captured here, encoded into the principal-tags
                    # claim after the whitelist filter below — the same `:k=v:`
                    # shape the Cognito resolver emits, gated by the same whitelist
                    # entry for the principal-tags claim key.
                    scope_principal_tags = hook_result.get('principal_tags', {})
                    logger.info(f'Post-auth hook returned additional claims: {list(additional_claims.keys())}')
                    
                    # Check if hook signals a redirect (e.g., confirmation required)
                    if 'error' in hook_result:
                        logger.warning(f'Post-auth hook returned error: {hook_result["error"]}')
                        hook_redirect = hook_result.get('redirect')
                        if hook_redirect:
                            return {
                                'status': '302',
                                'statusDescription': 'Found',
                                'headers': {
                                    'location': [{'key': 'Location', 'value': hook_redirect}],
                                    'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}]
                                }
                            }
                        if hook_fail_closed:
                            return {
                                'status': '403',
                                'statusDescription': 'Forbidden',
                                'body': 'Authentication denied by identity hook'
                            }
            except urllib.error.URLError as e:
                logger.error(f'Post-auth hook request failed: {e}')
                if hook_fail_closed:
                    return {
                        'status': '503',
                        'statusDescription': 'Service Unavailable',
                        'body': 'Identity resolution unavailable'
                    }
            except Exception as e:
                logger.error(f'Post-auth hook unexpected error: {e}')
                if hook_fail_closed:
                    return {
                        'status': '503',
                        'statusDescription': 'Service Unavailable',
                        'body': 'Identity resolution unavailable'
                    }
        
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
            **additional_claims,  # Merge claims from post-auth identity hook
            "jti": jti,
            "exp": azure_exp,  # Match Azure AD expiration
            "iat": int(time.time()),
            "iss": redirect_uri,
            "idp": payload.get("iss")
        }

        # Scope principal tags -> the AWS principal-tags claim, in the same
        # `:k=v:` shape the Cognito resolver and the pre-token injector emit, so
        # the edge/AssumeRole path reads one consistent format regardless of IdP.
        # Gated by the whitelist exactly like a role claim: when a whitelist is
        # configured the tag claim key must be in it; with no whitelist the
        # fallback allows it (consistent with the claim-filter fallback above).
        if scope_principal_tags:
            tag_allowed = (PRINCIPAL_TAGS_CLAIM in whitelist) if jwt_claims_whitelist_str else True
            if tag_allowed:
                encoded_tags = encode_principal_tags(scope_principal_tags)
                if encoded_tags is not None:
                    session_payload[PRINCIPAL_TAGS_CLAIM] = encoded_tags
        
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
        
        # Store Entra refresh token for silent session renewal (only when refresh is enabled)
        enable_refresh = config.get('enable_refresh', 'false').lower() == 'true'
        refresh_token = token_response.get('refresh_token')
        if enable_refresh and refresh_token and table_name:
            try:
                refresh_ttl = int(time.time()) + (30 * 24 * 60 * 60)  # 30 days
                dynamodb.put_item(
                    TableName=table_name,
                    Item={
                        'pk': {'S': f'REFRESH#{jti}'},
                        'sk': {'S': f'REFRESH#{jti}'},
                        'refresh_token': {'S': refresh_token},
                        'user_id': {'S': user_id or ''},
                        'customer_id': {'S': additional_claims.get('customer_id', '')},
                        'createdAt': {'N': str(int(time.time()))},
                        'expiresAt': {'N': str(refresh_ttl)}
                    }
                )
                logger.info(f'Refresh token stored in DynamoDB: REFRESH#{jti}')
            except Exception as e:
                logger.error(f'Failed to store refresh token in DynamoDB: {e}')
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(session_payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        # Scope-token size guard — refuse (never truncate) an over-budget token.
        # Mirrors the Cognito mint's guard exactly: the check runs on the
        # ASSEMBLED token (header + payload + a 43-byte base64url HS256 signature
        # segment, plus the two '.' separators) BEFORE the cookie is built, so a
        # partial set of resolver-merged role claims / scope principal tags can
        # never be signed. A grid that cannot fit signals a mismodelled
        # assignment, fixed in the assignment model, not coped with here.
        scope_token_max_bytes = int(config.get('scope_token_max_bytes', '7168'))
        if scope_token_exceeds(header_b64, payload_b64, scope_token_max_bytes):
            assembled_len = assembled_token_len(header_b64, payload_b64)
            logger.error(
                f'Assembled session token is {assembled_len} bytes, over '
                f'{scope_token_max_bytes}; refusing mint'
            )
            return {
                'status': '500',
                'statusDescription': 'Internal Server Error',
                'body': 'Session scope exceeds the token size limit'
            }

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

        # RS256 web-identity half: when enabled, ALSO mint a horton-signed RS256
        # token for sts:AssumeRoleWithWebIdentity, carrying the SAME principal-tags
        # brand claim and the SAME expiry as the session cookie (one source, so
        # the two tokens can never disagree about the brand). Delivered as a
        # separate __Secure/__Host cookie the operator API reads for the STS call.
        web_identity_cookie = None
        if web_identity.is_enabled(config):
            try:
                # Flat-permission model: carry the resolver's UI/scope claims in
                # the RS256 token too (today they reach only the HMAC cookie).
                # Whitelist-gate them exactly like the HMAC side — when a
                # whitelist is configured a claim must be in it; with no
                # whitelist the fallback allows it (matches the claim-filter
                # fallback above). Reserved/tag claims are dropped by the mint.
                wi_additional_claims = {}
                if additional_claims:
                    if jwt_claims_whitelist_str:
                        wi_additional_claims = {
                            k: v for k, v in additional_claims.items() if k in whitelist
                        }
                    else:
                        wi_additional_claims = dict(additional_claims)
                wi_token = web_identity.mint_web_identity_token(
                    config,
                    WEB_IDENTITY_KEY_REGION,
                    subject=user_id,
                    principal_tags_claim=PRINCIPAL_TAGS_CLAIM,
                    principal_tags_value=session_payload.get(PRINCIPAL_TAGS_CLAIM),
                    ttl_exp=azure_exp_timestamp,
                    username=payload.get('preferred_username'),
                    additional_claims=wi_additional_claims,
                    max_bytes=scope_token_max_bytes,
                )
                web_identity_cookie = (
                    f'{cookie_prefix}web_identity={wi_token}; '
                    f'HttpOnly; Secure; SameSite=Lax; '
                    f'Path=/; '
                    f'Expires={expires_str}'
                    f'{domain_attr}'
                )
                logger.info('RS256 web-identity token minted (KMS kms:Sign)')
            except Exception as e:
                # Fail closed on the role-token half: if we cannot mint it, do not
                # hand back a session that silently lacks role-assumption ability.
                logger.error(f'Failed to mint web-identity token: {e}')
                return {
                    'status': '500',
                    'statusDescription': 'Internal Server Error',
                    'body': 'Role token minting failed'
                }
        
        # Clear oauth_state cookie
        state_cookie = f'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0{domain_attr}'
        
        # Clear code_verifier cookie
        verifier_cookie = f'code_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0{domain_attr}'
        
        logger.info('Step 4: Building redirect response')
        set_cookie_headers = [
            {'key': 'Set-Cookie', 'value': auth_cookie},
            {'key': 'Set-Cookie', 'value': azure_cookie},
        ]
        if web_identity_cookie:
            set_cookie_headers.append({'key': 'Set-Cookie', 'value': web_identity_cookie})
        set_cookie_headers.append({'key': 'Set-Cookie', 'value': state_cookie})
        set_cookie_headers.append({'key': 'Set-Cookie', 'value': verifier_cookie})
        response = {
            'status': '302',
            'statusDescription': 'Found',
            'headers': {
                'location': [{'key': 'Location', 'value': redirect_path}],
                'set-cookie': set_cookie_headers,
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
