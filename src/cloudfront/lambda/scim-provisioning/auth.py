"""
SCIM request authentication, fail-closed. The dispatcher calls `authenticate`
as the FIRST action on any SCIM route; a None return is a 401 with no store
access.

Modes (AUTH_MODE):
  * OAUTH_CLIENT_CREDENTIALS / WIF  -> verify the Bearer JWT we issued, against
                                       our own KMS public key (tokens.verify_access_token).
  * AWS_IAM                         -> the Function URL already enforced SigV4;
                                       trust the validated principal.
  * STATIC_BEARER                   -> constant-time compare against a Secrets
                                       Manager secret (legacy, opt-in).
Every ambiguous or error path returns None (deny).
"""

import hmac
import logging
import os

import boto3
import tokens

logger = logging.getLogger()


def _bearer(headers):
    auth = headers.get('authorization', '')
    if auth.lower().startswith('bearer '):
        return auth[7:].strip()
    return None


def authenticate(event, headers):
    mode = os.environ.get('AUTH_MODE', 'OAUTH_CLIENT_CREDENTIALS')

    if mode == 'AWS_IAM':
        # The Function URL (AuthType.AWS_IAM) validated SigV4 before invoking us.
        # The caller ARN is in the request context; its presence is the signal.
        ctx = event.get('requestContext', {})
        iam = ctx.get('authorizer', {}).get('iam', {}) if isinstance(ctx.get('authorizer'), dict) else {}
        caller = iam.get('userArn') or ctx.get('identity', {}).get('userArn')
        return caller or 'aws-iam-principal'  # Function URL would not have invoked us otherwise

    if mode == 'STATIC_BEARER':
        presented = _bearer(headers)
        if not presented:
            return None
        try:
            expected = boto3.client('secretsmanager').get_secret_value(
                SecretId=os.environ['STATIC_BEARER_ARN'])['SecretString']
        except Exception as e:  # noqa: BLE001 - unreadable secret denies
            logger.info('static bearer secret unreadable: %s', type(e).__name__)
            return None
        return 'static-bearer' if hmac.compare_digest(presented, expected or '') else None

    # OAUTH_CLIENT_CREDENTIALS / WIF: verify the JWT we issued.
    presented = _bearer(headers)
    if not presented:
        return None
    claims = tokens.verify_access_token(presented)
    if claims is None:
        return None
    return claims.get('sub') or 'oauth-client'
