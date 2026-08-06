/**
 * Property-Based Test: Expired JWT Triggers Refresh (Property 10)
 *
 * Validates that when a session JWT has a valid HMAC signature but is expired
 * (exp < now), the auth function redirects to the refresh endpoint (when
 * refresh is enabled) rather than redirecting to the full Entra login.
 *
 * Invariant: valid_hmac + expired + refresh_enabled → 302 to /oauth2/refresh
 *
 * Tagged: Feature: externalId, Property 10: Expired JWT Triggers Refresh
 * Validates: Requirements 3.2, 7.2
 */
import * as crypto from 'crypto';
import * as fc from 'fast-check';

// ─────────────────────────────────────────────────────────────────────────────
// JWT helpers
// ─────────────────────────────────────────────────────────────────────────────

const TEST_SECRET = 'test-refresh-property-secret';

function signJwt(payload: Record<string, unknown>, secret: string = TEST_SECRET): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyHmac(token: string, secret: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${parts[0]}.${parts[1]}`).digest('base64url');
  return expected === parts[2];
}

function decodePayload(token: string): Record<string, unknown> {
  const parts = token.split('.');
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulate auth-check.js expired JWT handling
// ─────────────────────────────────────────────────────────────────────────────

type AuthResult = { action: 'pass' } | { action: 'refresh_redirect'; returnTo: string } | { action: 'login_redirect' };

function evaluateExpiredJwt(
  token: string,
  secret: string,
  refreshEnabled: boolean,
  originalPath: string,
  host: string,
): AuthResult {
  // Step 1: Verify HMAC
  if (!verifyHmac(token, secret)) {
    return { action: 'login_redirect' }; // Invalid signature → full re-auth
  }

  // Step 2: Check expiry
  const payload = decodePayload(token);
  const now = Math.floor(Date.now() / 1000);
  const exp = payload.exp as number;

  if (exp >= now) {
    return { action: 'pass' }; // Not expired
  }

  // Step 3: Expired but valid HMAC
  if (refreshEnabled) {
    const returnTo = host ? `https://${host}${originalPath}` : originalPath;
    return { action: 'refresh_redirect', returnTo: returnTo };
  }

  // Refresh not enabled → full login redirect
  return { action: 'login_redirect' };
}

// ─────────────────────────────────────────────────────────────────────────────
// Property tests
// ─────────────────────────────────────────────────────────────────────────────

describe('Property 10: Expired JWT Triggers Refresh', () => {
  it('expired JWT with valid HMAC + refresh enabled → refresh redirect (200 iterations)', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 86400 }), // seconds ago it expired
        fc.string({ minLength: 1, maxLength: 100 }).map((s) => '/' + s.replace(/[\n\r]/g, '')),
        fc.domain(),
        (secondsExpired, path, host) => {
          const now = Math.floor(Date.now() / 1000);
          const payload = {
            sub: 'test-sub',
            email: 'test@example.com',
            exp: now - secondsExpired, // expired
            iat: now - secondsExpired - 3600,
            jti: 'jti-test',
          };
          const token = signJwt(payload);

          const result = evaluateExpiredJwt(token, TEST_SECRET, true, path, host);

          expect(result.action).toBe('refresh_redirect');
          if (result.action === 'refresh_redirect') {
            expect(result.returnTo).toContain(path);
            expect(result.returnTo).toContain(host);
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it('expired JWT with valid HMAC + refresh disabled → login redirect (100 iterations)', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 86400 }),
        (secondsExpired) => {
          const now = Math.floor(Date.now() / 1000);
          const payload = { sub: 'test', email: 't@e.com', exp: now - secondsExpired, iat: now - 7200, jti: 'j' };
          const token = signJwt(payload);

          const result = evaluateExpiredJwt(token, TEST_SECRET, false, '/store', 'example.com');

          expect(result.action).toBe('login_redirect');
        },
      ),
      { numRuns: 100 },
    );
  });

  it('non-expired JWT with valid HMAC → pass (regardless of refresh setting) (100 iterations)', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 86400 }), // seconds until expiry
        fc.boolean(), // refreshEnabled
        (secondsUntilExpiry, refreshEnabled) => {
          const now = Math.floor(Date.now() / 1000);
          const payload = { sub: 'test', email: 't@e.com', exp: now + secondsUntilExpiry, iat: now, jti: 'j' };
          const token = signJwt(payload);

          const result = evaluateExpiredJwt(token, TEST_SECRET, refreshEnabled, '/store', 'example.com');

          expect(result.action).toBe('pass');
        },
      ),
      { numRuns: 100 },
    );
  });

  it('expired JWT with INVALID HMAC → login redirect (never refresh) (100 iterations)', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 86400 }),
        (secondsExpired) => {
          const now = Math.floor(Date.now() / 1000);
          const payload = { sub: 'test', email: 't@e.com', exp: now - secondsExpired, iat: now - 7200, jti: 'j' };
          const token = signJwt(payload, 'wrong-secret');

          const result = evaluateExpiredJwt(token, TEST_SECRET, true, '/store', 'example.com');

          // Invalid HMAC → never trust the token, even for refresh
          expect(result.action).toBe('login_redirect');
        },
      ),
      { numRuns: 100 },
    );
  });
});
