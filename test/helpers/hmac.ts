import * as crypto from 'crypto';

/**
 * Sign a JWT payload using HMAC-SHA256, producing a compact JWT string.
 *
 * This mirrors the signing logic in the OAuth2 callback Lambda — used by
 * tests to create valid tokens for verification testing.
 *
 * @param payload - The JWT claims object
 * @param secret - The HMAC signing secret
 * @param headerOverrides - Optional header field overrides (e.g., to test algorithm confusion)
 * @returns The signed JWT string (header.payload.signature)
 *
 * @example
 * const token = signJwt({ sub: 'user-1', email: 'user@example.com', exp: future() }, 'my-secret');
 */
export function signJwt(
  payload: Record<string, unknown>,
  secret: string,
  headerOverrides?: Record<string, unknown>,
): string {
  const header = { alg: 'HS256', typ: 'JWT', ...headerOverrides };

  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest('base64url');

  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Verify an HMAC-SHA256 signed JWT and return the decoded payload.
 *
 * This mirrors the verification logic in auth-check.js — used by tests to
 * confirm tokens are correctly formed.
 *
 * @param token - The JWT string to verify
 * @param secret - The HMAC secret to verify against
 * @returns The decoded payload if valid, or null if verification fails
 */
export function verifyJwt(token: string, secret: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest('base64url');

  if (!constantTimeCompare(expectedSignature, parts[2])) {
    return null;
  }

  try {
    return JSON.parse(base64urlDecode(parts[1]));
  } catch {
    return null;
  }
}

/**
 * Decode a base64url-encoded string to a UTF-8 string.
 *
 * @param str - The base64url-encoded string
 * @returns The decoded UTF-8 string
 */
export function base64urlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Encode a string to base64url format (no padding).
 *
 * @param str - The string to encode
 * @returns The base64url-encoded string without padding
 */
export function base64urlEncode(str: string): string {
  return Buffer.from(str, 'utf-8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Constant-time string comparison to prevent timing attacks.
 *
 * @param a - First string
 * @param b - Second string
 * @returns true if strings are identical
 */
function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
