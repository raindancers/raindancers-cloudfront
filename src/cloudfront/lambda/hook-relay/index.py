"""Hook relay: carries the session Lambda@Edge's identity-link call into a VPC.

Lambda@Edge cannot join a VPC, so it cannot reach a private service. It can invoke
a regular Lambda with `lambda:Invoke`. This function is that Lambda. It runs in the
VPC, calls the private URL of the identity-linking hook, and returns the answer.

Input (the edge function's identity payload):   {"sub": ..., "email": ..., "provider": ...}
Output:                                          {"status": <http status>, "body": <object>}

It proves who it is to the hook with a short-lived web identity token from AWS STS
(`GetWebIdentityToken`, IAM outbound identity federation). The hook checks the token's
signature against the issuer's public keys, plus the issuer, the audience and the
role. There is no shared secret. The token is kept in memory and replaced when it has
less than TOKEN_REFRESH_MARGIN_SECONDS left, so a warm instance makes no STS call on
a login.

Settings come from environment variables set by the HookRelay construct:
  HOOK_URL                  private URL of the hook, e.g. http://medusa-api.ns:9000/hooks/identity-link
  HOOK_AUDIENCE             the `aud` the hook expects
  STS_REGION                region of the regional STS endpoint (GetWebIdentityToken is not on the global one)
  HOOK_TIMEOUT_SECONDS      timeout of the call to the hook (default 2.5)
"""

import json
import logging
import os
import time
import urllib.error
import urllib.request

import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TOKEN_LIFETIME_SECONDS = 300
TOKEN_REFRESH_MARGIN_SECONDS = 60
SIGNING_ALGORITHM = 'ES384'

_sts = None
_token = None
_token_expires_at = 0.0


def _sts_client():
    global _sts
    if _sts is None:
        region = os.environ['STS_REGION']
        _sts = boto3.client(
            'sts',
            region_name=region,
            endpoint_url=f'https://sts.{region}.amazonaws.com',
            config=Config(retries={'max_attempts': 2, 'mode': 'standard'}, connect_timeout=2, read_timeout=3),
        )
    return _sts


def get_token(now=None):
    """Return a web identity token for the hook, from memory when it still has time left."""
    global _token, _token_expires_at
    now = time.time() if now is None else now
    if _token and _token_expires_at - now > TOKEN_REFRESH_MARGIN_SECONDS:
        return _token
    client = _sts_client()
    if not hasattr(client, 'get_web_identity_token'):
        # The Lambda runtime's boto3 predates GetWebIdentityToken. Say so plainly.
        raise RuntimeError('boto3 in this runtime has no get_web_identity_token; use a newer runtime')
    resp = client.get_web_identity_token(
        Audience=[os.environ['HOOK_AUDIENCE']],
        SigningAlgorithm=SIGNING_ALGORITHM,
        DurationSeconds=TOKEN_LIFETIME_SECONDS,
    )
    _token = resp['WebIdentityToken']
    _token_expires_at = resp['Expiration'].timestamp()
    return _token


def call_hook(identity):
    """POST the identity to the hook. Returns (status_code, body_dict)."""
    data = json.dumps(identity, separators=(',', ':')).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {get_token()}',
    }
    req = urllib.request.Request(os.environ['HOOK_URL'], data=data, headers=headers, method='POST')
    timeout = float(os.environ.get('HOOK_TIMEOUT_SECONDS', '2.5'))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.getcode(), json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = {}
        try:
            body = json.loads(e.read().decode('utf-8'))
        except Exception:
            pass
        return e.code, body


def lambda_handler(event, context):
    try:
        status, body = call_hook(event)
    except Exception as e:
        # Never put the identity or the token in the log: only the error type.
        logger.error(f'hook relay failed: {type(e).__name__}')
        return {'status': 503, 'body': {'type': 'unavailable'}}
    return {'status': status, 'body': body}
