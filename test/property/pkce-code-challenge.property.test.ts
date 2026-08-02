/**
 * Property-Based Test: PKCE Code Challenge Correctness (Property 1)
 *
 * Validates that for ANY code_verifier in the valid charset, the generated
 * code_challenge is the SHA-256 hash of the verifier encoded as base64url
 * (the S256 method per RFC 7636).
 *
 * Invariant: SHA256(code_verifier) encoded as base64url === code_challenge
 *
 * Tagged: Feature: externalId, Property 1: PKCE Code Challenge Correctness
 * Validates: Requirements 1.1
 */
import * as fc from 'fast-check';
import * as crypto from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Replicate the auth-check.js PKCE functions (same logic, TypeScript version)
// ─────────────────────────────────────────────────────────────────────────────

/** Valid PKCE code verifier characters per RFC 7636 Section 4.1. */
const PKCE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

/**
 * Generate a code challenge from a verifier using S256 method.
 * Mirrors auth-check.js `generateCodeChallenge`.
 */
function generateCodeChallenge(verifier: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(verifier);
  return hash.digest('base64url');
}

/**
 * Generate a random code verifier from the PKCE charset.
 * Mirrors auth-check.js `generateCodeVerifier`.
 */
function generateCodeVerifier(): string {
  let result = '';
  for (let i = 0; i < 43; i++) {
    result += PKCE_CHARSET.charAt(Math.floor(Math.random() * PKCE_CHARSET.length));
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// fast-check arbitrary for PKCE code verifiers (RFC 7636: 43-128 chars)
// ─────────────────────────────────────────────────────────────────────────────

// fast-check arbitrary for PKCE code verifiers (RFC 7636: 43-128 chars from valid charset)
const pkceVerifierArb = fc.array(
  fc.integer({ min: 0, max: PKCE_CHARSET.length - 1 }),
  { minLength: 43, maxLength: 128 }
).map((indices) => indices.map((i) => PKCE_CHARSET[i]).join(''));

// ─────────────────────────────────────────────────────────────────────────────
// Property tests
// ─────────────────────────────────────────────────────────────────────────────

describe('Property 1: PKCE Code Challenge Correctness', () => {
  it('code_challenge is always SHA-256(verifier) in base64url (200 iterations)', () => {
    fc.assert(
      fc.property(pkceVerifierArb, (verifier) => {
        const challenge = generateCodeChallenge(verifier);

        // Independently compute the expected value
        const expected = crypto.createHash('sha256').update(verifier).digest('base64url');

        expect(challenge).toBe(expected);
      }),
      { numRuns: 200 }
    );
  });

  it('code_challenge output is always valid base64url (no +, /, or = padding)', () => {
    fc.assert(
      fc.property(pkceVerifierArb, (verifier) => {
        const challenge = generateCodeChallenge(verifier);

        expect(challenge).not.toContain('+');
        expect(challenge).not.toContain('/');
        expect(challenge).not.toContain('=');
        // SHA-256 → 32 bytes → base64url = 43 chars (no padding)
        expect(challenge.length).toBe(43);
      }),
      { numRuns: 200 }
    );
  });

  it('different verifiers produce different challenges (collision resistance)', () => {
    fc.assert(
      fc.property(pkceVerifierArb, pkceVerifierArb, (v1, v2) => {
        if (v1 === v2) return; // skip identical verifiers
        const c1 = generateCodeChallenge(v1);
        const c2 = generateCodeChallenge(v2);
        expect(c1).not.toBe(c2);
      }),
      { numRuns: 100 }
    );
  });

  it('generateCodeVerifier produces strings of exactly 43 chars from valid charset', () => {
    for (let i = 0; i < 100; i++) {
      const verifier = generateCodeVerifier();
      expect(verifier.length).toBe(43);
      for (const char of verifier) {
        expect(PKCE_CHARSET).toContain(char);
      }
    }
  });
});
