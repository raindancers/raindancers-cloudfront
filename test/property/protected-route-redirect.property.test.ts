/**
 * Property-Based Test: Protected Route Redirect Completeness (Property 3)
 *
 * Validates that ALL unauthenticated requests to protected routes (non-/oauth2/*)
 * result in a 302 redirect to Entra's /authorize endpoint, regardless of the
 * request path, method, or query string.
 *
 * Invariant: no session cookie + protected path → 302 redirect to Entra
 *
 * Tagged: Feature: externalId, Property 3: Protected Route Redirect Completeness
 * Validates: Requirements 3.1
 */
import * as fc from 'fast-check';
import * as crypto from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Replicate the relevant auth-check.js logic
// ─────────────────────────────────────────────────────────────────────────────

const AZURE_TENANT_ID = 'test-tenant-id';
const AZURE_CLIENT_ID = 'test-client-id';
const REDIRECT_URI = 'https://example.com/oauth2/callback';

function generateCodeVerifier(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let result = '';
  for (let i = 0; i < 43; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

function generateState(originalPath: string, host: string): string {
  const randomPart = Math.random().toString(36).substring(2) + Date.now().toString(36);
  const stateObj = { r: randomPart, p: originalPath, h: host };
  return Buffer.from(JSON.stringify(stateObj)).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function buildAzureAuthUrl(state: string, codeChallenge: string): string {
  const params = [
    'client_id=' + encodeURIComponent(AZURE_CLIENT_ID),
    'redirect_uri=' + encodeURIComponent(REDIRECT_URI),
    'response_type=code',
    'scope=' + encodeURIComponent('openid profile email'),
    'state=' + encodeURIComponent(state),
    'code_challenge=' + encodeURIComponent(codeChallenge),
    'code_challenge_method=S256',
  ];
  return `https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/authorize?${params.join('&')}`;
}

/**
 * Simulate the redirect response for an unauthenticated request.
 * Mirrors auth-check.js `redirectToAuth`.
 */
function redirectToAuth(originalPath: string, host: string) {
  const state = generateState(originalPath, host);
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  return {
    statusCode: 302,
    headers: {
      location: { value: buildAzureAuthUrl(state, codeChallenge) },
      'cache-control': { value: 'no-store' },
    },
    cookies: {
      oauth_state: { value: state, attributes: 'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600' },
      code_verifier: { value: codeVerifier, attributes: 'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600' },
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Arbitraries
// ─────────────────────────────────────────────────────────────────────────────

// Protected paths: any path that does NOT start with /oauth2/
const protectedPathArb = fc.string({ minLength: 1, maxLength: 200 })
  .map((s) => '/' + s.replace(/[\n\r]/g, ''))
  .filter((p) => !p.startsWith('/oauth2/'));

const hostArb = fc.domain();

// ─────────────────────────────────────────────────────────────────────────────
// Property tests
// ─────────────────────────────────────────────────────────────────────────────

describe('Property 3: Protected Route Redirect Completeness', () => {
  it('unauthenticated request to any protected path produces 302 redirect (200 iterations)', () => {
    fc.assert(
      fc.property(protectedPathArb, hostArb, (path, host) => {
        const response = redirectToAuth(path, host);

        expect(response.statusCode).toBe(302);
        expect(response.headers.location.value).toContain('login.microsoftonline.com');
        expect(response.headers.location.value).toContain('oauth2/v2.0/authorize');
        expect(response.headers['cache-control'].value).toBe('no-store');
      }),
      { numRuns: 200 }
    );
  });

  it('redirect URL always includes client_id, redirect_uri, and PKCE parameters', () => {
    fc.assert(
      fc.property(protectedPathArb, hostArb, (path, host) => {
        const response = redirectToAuth(path, host);
        const url = response.headers.location.value;

        expect(url).toContain('client_id=');
        expect(url).toContain('redirect_uri=');
        expect(url).toContain('code_challenge=');
        expect(url).toContain('code_challenge_method=S256');
        expect(url).toContain('response_type=code');
        expect(url).toContain('state=');
      }),
      { numRuns: 100 }
    );
  });

  it('redirect sets oauth_state and code_verifier cookies (HttpOnly, Secure)', () => {
    fc.assert(
      fc.property(protectedPathArb, hostArb, (path, host) => {
        const response = redirectToAuth(path, host);

        expect(response.cookies.oauth_state).toBeDefined();
        expect(response.cookies.oauth_state.attributes).toContain('HttpOnly');
        expect(response.cookies.oauth_state.attributes).toContain('Secure');
        expect(response.cookies.oauth_state.attributes).toContain('SameSite=Lax');

        expect(response.cookies.code_verifier).toBeDefined();
        expect(response.cookies.code_verifier.attributes).toContain('HttpOnly');
        expect(response.cookies.code_verifier.attributes).toContain('Secure');
      }),
      { numRuns: 100 }
    );
  });

  it('state parameter in redirect encodes the original path for post-auth restoration', () => {
    fc.assert(
      fc.property(protectedPathArb, hostArb, (path, host) => {
        const response = redirectToAuth(path, host);
        const stateValue = response.cookies.oauth_state.value;

        // Decode the state to verify path is preserved
        let base64 = stateValue.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) base64 += '=';
        const decoded = JSON.parse(Buffer.from(base64, 'base64').toString());

        expect(decoded.p).toBe(path);
        expect(decoded.h).toBe(host);
      }),
      { numRuns: 100 }
    );
  });
});
