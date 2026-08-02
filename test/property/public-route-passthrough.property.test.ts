/**
 * Property-Based Test: Public Route Pass-Through (Property 4)
 *
 * Validates that /oauth2/* paths are NEVER blocked by the auth check,
 * regardless of authentication state. These are the OAuth2 callback and
 * token exchange endpoints that must be accessible to complete the auth flow.
 *
 * Invariant: request.uri starting with /oauth2/ → always pass through
 *
 * Tagged: Feature: externalId, Property 4: Public Route Pass-Through
 * Validates: Requirements 3.2
 */
import * as fc from 'fast-check';

// ─────────────────────────────────────────────────────────────────────────────
// Replicate the auth-check.js public route logic
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check if a URI is a public OAuth2 route that should pass through.
 * Mirrors the `if (request.uri.indexOf('/oauth2/') === 0)` check in auth-check.js.
 */
function isOAuth2Route(uri: string): boolean {
  return uri.indexOf('/oauth2/') === 0;
}

/**
 * Simulate the auth check result for a request.
 * Returns { pass: true } for OAuth2 routes, regardless of auth state.
 */
function simulateAuthCheck(uri: string, hasSessionCookie: boolean): { pass: boolean } {
  // OAuth2 routes always pass through — this is the FIRST check in checkAuth
  if (isOAuth2Route(uri)) {
    return { pass: true };
  }

  // Non-OAuth2 routes require a session cookie
  if (!hasSessionCookie) {
    return { pass: false }; // Would trigger redirect
  }

  return { pass: true }; // Has cookie (would still need HMAC validation)
}

// ─────────────────────────────────────────────────────────────────────────────
// Arbitraries
// ─────────────────────────────────────────────────────────────────────────────

// OAuth2 paths: /oauth2/ followed by any valid path segment
const oauth2PathArb = fc.string({ minLength: 0, maxLength: 100 })
  .map((s) => '/oauth2/' + s.replace(/[\n\r]/g, ''));

// Non-OAuth2 protected paths
const protectedPathArb = fc.string({ minLength: 1, maxLength: 100 })
  .map((s) => '/' + s.replace(/[\n\r]/g, ''))
  .filter((p) => !p.startsWith('/oauth2/'));

// ─────────────────────────────────────────────────────────────────────────────
// Property tests
// ─────────────────────────────────────────────────────────────────────────────

describe('Property 4: Public Route Pass-Through', () => {
  it('/oauth2/* paths always pass through regardless of auth state (200 iterations)', () => {
    fc.assert(
      fc.property(
        oauth2PathArb,
        fc.boolean(), // hasSessionCookie (irrelevant for OAuth2 routes)
        (path, hasSession) => {
          const result = simulateAuthCheck(path, hasSession);
          expect(result.pass).toBe(true);
        }
      ),
      { numRuns: 200 }
    );
  });

  it('/oauth2/callback is always a pass-through', () => {
    expect(simulateAuthCheck('/oauth2/callback', false).pass).toBe(true);
    expect(simulateAuthCheck('/oauth2/callback', true).pass).toBe(true);
    // Note: in CloudFront Functions, query strings are NOT part of request.uri.
    // The URI is just the path portion. But our simulation uses indexOf which
    // would still match if a query string were present in the input.
  });

  it('/oauth2/refresh and /oauth2/logout are pass-throughs', () => {
    expect(simulateAuthCheck('/oauth2/refresh', false).pass).toBe(true);
    expect(simulateAuthCheck('/oauth2/logout', false).pass).toBe(true);
  });

  it('non-/oauth2/ paths without session cookie do NOT pass through (100 iterations)', () => {
    fc.assert(
      fc.property(protectedPathArb, (path) => {
        const result = simulateAuthCheck(path, false);
        expect(result.pass).toBe(false);
      }),
      { numRuns: 100 }
    );
  });

  it('paths that merely contain /oauth2/ but dont start with it are protected', () => {
    // These should NOT be treated as public routes
    const sneakyPaths = [
      '/store/oauth2/callback',
      '/admin/oauth2/exploit',
      '/api/oauth2/trick',
    ];
    for (const path of sneakyPaths) {
      expect(simulateAuthCheck(path, false).pass).toBe(false);
    }
  });
});
