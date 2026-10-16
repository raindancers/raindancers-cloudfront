"""
SCIM 2.0 provisioning service handler (reusable, IdP-agnostic).

One Lambda, behind a Function URL, serving three surfaces dispatched on
(method, path):

  * POST  <tokenEndpointPath>  -> OAuth 2.0 client-credentials token endpoint
                                  (or, in WIF mode, the RFC 7523 JWT bearer
                                  assertion exchange). Mints a short-lived,
                                  KMS-signed access token.
  * GET   <jwksPath>           -> JWKS document (the token signing public key),
                                  public and unauthenticated.
  * *     <scimBasePath>/...    -> SCIM 2.0 Users/Groups/discovery, authenticated
                                  first and fail-closed.

Configuration is passed entirely via environment variables set by the
`ScimProvisioningService` construct, so the handler carries no consumer, IdP,
brand, or domain specifics:

  AUTH_MODE            OAUTH_CLIENT_CREDENTIALS | AWS_IAM | WIF | STATIC_BEARER
  SCIM_BASE_PATH       e.g. /scim/v2
  TOKEN_ENDPOINT_PATH  e.g. /oauth2/token
  JWKS_PATH            e.g. /.well-known/jwks.json
  TABLE_NAME           the provisioned-directory DynamoDB table
  SIGNING_KEY_ID       KMS asymmetric key id used to sign access tokens
  TOKEN_ISSUER         iss/aud stamped on issued tokens and required on SCIM
  ACCESS_TOKEN_TTL     issued-token lifetime in seconds
  CLIENT_SECRET_ARN    (OAUTH) Secrets Manager secret holding the client secret
  STATIC_BEARER_ARN    (STATIC_BEARER) Secrets Manager secret holding the token
  WIF_ASSERTION_ISSUER / WIF_ASSERTION_JWKS_URI / WIF_EXPECTED_AUDIENCE /
  WIF_EXPECTED_AZP     (WIF) the IdP assertion trust parameters

The modules this file is split into keep each concern testable in isolation:
`store` (DynamoDB item model), `tokens` (mint/verify/JWKS), `scim` (lifecycle
and discovery routes), `auth` (the fail-closed authenticator).
"""

import json
import logging
import os

import auth
import scim
import tokens

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _config():
    return {
        'auth_mode': os.environ.get('AUTH_MODE', 'OAUTH_CLIENT_CREDENTIALS'),
        'scim_base_path': os.environ.get('SCIM_BASE_PATH', '/scim/v2'),
        'token_endpoint_path': os.environ.get('TOKEN_ENDPOINT_PATH', '/oauth2/token'),
        'jwks_path': os.environ.get('JWKS_PATH', '/.well-known/jwks.json'),
    }


def _method_and_path(event):
    """Extract (METHOD, path) from a Lambda Function URL proxy event."""
    ctx = event.get('requestContext', {}).get('http', {})
    method = (ctx.get('method') or event.get('httpMethod') or 'GET').upper()
    path = ctx.get('path') or event.get('rawPath') or '/'
    # Normalise a trailing slash (except root) so routing is stable.
    if len(path) > 1 and path.endswith('/'):
        path = path.rstrip('/')
    return method, path


def _lower_headers(event):
    """Function URLs lowercase header names, but normalise defensively."""
    return {str(k).lower(): v for k, v in (event.get('headers') or {}).items()}


def response(status, body, content_type='application/scim+json'):
    return {
        'statusCode': status,
        'headers': {'content-type': content_type},
        'body': body if isinstance(body, str) else json.dumps(body),
    }


def handler(event, context):
    cfg = _config()
    method, path = _method_and_path(event)
    headers = _lower_headers(event)

    scim_base = cfg['scim_base_path']

    # Token endpoint (OAUTH / WIF). Unauthenticated at the HTTP layer: it IS the
    # authentication exchange.
    if method == 'POST' and path == cfg['token_endpoint_path']:
        return tokens.token_endpoint(event, headers)

    # JWKS document: public by design (it is a public key).
    if method == 'GET' and path == cfg['jwks_path']:
        return tokens.jwks_document()

    # SCIM surface: authenticate FIRST, fail-closed, before any routing/parsing.
    if path == scim_base or path.startswith(scim_base + '/'):
        principal = auth.authenticate(event, headers)
        if principal is None:
            return response(401, scim.scim_error('401', 'Unauthorized'))
        return scim.dispatch(method, path, scim_base, event)

    return response(404, scim.scim_error('404', 'Not found'))
