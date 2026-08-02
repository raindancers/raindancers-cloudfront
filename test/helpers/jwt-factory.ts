import { signJwt } from './hmac';

/**
 * Default HMAC secret used across tests unless overridden.
 */
export const TEST_SECRET = 'test-hmac-secret-do-not-use-in-production';

/**
 * Default old/rotated HMAC secret for testing dual-key validation.
 */
export const TEST_OLD_SECRET = 'test-hmac-secret-old-rotated';

export interface JwtClaimsOptions {
  /** Entra subject identifier. @default 'entra-sub-12345' */
  readonly sub?: string;
  /** Customer email. @default 'customer@example.com' */
  readonly email?: string;
  /** Medusa customer ID. @default 'cust_abc123' */
  readonly customerId?: string;
  /** Roles array. @default [] */
  readonly roles?: string[];
  /** Issued-at timestamp. @default current time */
  readonly iat?: number;
  /** Expiry timestamp. @default 1 hour from now */
  readonly exp?: number;
  /** Issuer. @default 'https://example.com/oauth2/callback' */
  readonly iss?: string;
  /** Unique session ID. @default 'sess_test123' */
  readonly jti?: string;
  /** Identity provider. @default 'https://login.microsoftonline.com/tenant-id/v2.0' */
  readonly idp?: string;
  /** Additional claims to merge. */
  readonly additionalClaims?: Record<string, unknown>;
}

/**
 * Create a valid session JWT payload with sensible test defaults.
 *
 * @param options - Override specific claims
 * @returns A complete JWT claims object
 *
 * @example
 * const claims = createJwtClaims({ exp: pastTimestamp() }); // expired token
 */
export function createJwtClaims(options: JwtClaimsOptions = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: options.sub ?? 'entra-sub-12345',
    email: options.email ?? 'customer@example.com',
    customer_id: options.customerId ?? 'cust_abc123',
    roles: options.roles ?? [],
    iat: options.iat ?? now,
    exp: options.exp ?? now + 3600,
    iss: options.iss ?? 'https://example.com/oauth2/callback',
    jti: options.jti ?? 'sess_test123',
    idp: options.idp ?? 'https://login.microsoftonline.com/tenant-id/v2.0',
    ...options.additionalClaims,
  };
}

/**
 * Create a signed, valid session JWT with default claims.
 *
 * @param options - Override specific claims
 * @param secret - HMAC secret to sign with. @default TEST_SECRET
 * @returns The signed JWT string
 *
 * @example
 * const token = createValidToken(); // valid for 1 hour
 * const expired = createValidToken({ exp: Math.floor(Date.now() / 1000) - 60 });
 */
export function createValidToken(options: JwtClaimsOptions = {}, secret: string = TEST_SECRET): string {
  const claims = createJwtClaims(options);
  return signJwt(claims, secret);
}

/**
 * Create a JWT that is expired but has a valid HMAC signature.
 *
 * @param secondsAgo - How many seconds in the past the token expired. @default 60
 * @param secret - HMAC secret to sign with. @default TEST_SECRET
 * @returns The signed, expired JWT string
 */
export function createExpiredToken(secondsAgo: number = 60, secret: string = TEST_SECRET): string {
  const now = Math.floor(Date.now() / 1000);
  return createValidToken({ exp: now - secondsAgo }, secret);
}

/**
 * Create a JWT with a tampered payload (valid structure but signature won't match).
 *
 * Signs with one secret, then re-signs the payload with a different secret,
 * producing a token where the signature doesn't match the payload.
 *
 * @param options - Claims for the original token
 * @returns A JWT string with mismatched signature
 */
export function createTamperedToken(options: JwtClaimsOptions = {}): string {
  return createValidToken(options, 'wrong-secret-tampered');
}

/**
 * Create a JWT signed with the old/rotated secret (for testing rotation grace period).
 *
 * @param options - Override specific claims
 * @returns The signed JWT string using TEST_OLD_SECRET
 */
export function createRotatedToken(options: JwtClaimsOptions = {}): string {
  return createValidToken(options, TEST_OLD_SECRET);
}

/**
 * Get a Unix timestamp N seconds in the future.
 *
 * @param seconds - Seconds from now
 * @returns Unix timestamp
 */
export function futureTimestamp(seconds: number = 3600): number {
  return Math.floor(Date.now() / 1000) + seconds;
}

/**
 * Get a Unix timestamp N seconds in the past.
 *
 * @param seconds - Seconds ago
 * @returns Unix timestamp
 */
export function pastTimestamp(seconds: number = 60): number {
  return Math.floor(Date.now() / 1000) - seconds;
}
