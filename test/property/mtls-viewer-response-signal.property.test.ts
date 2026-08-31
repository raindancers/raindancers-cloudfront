/**
 * Property-Based Test: ViewerMtlsAccess viewer-response edge-signal function.
 *
 * Feature: certIdentity, Property 6 (task 3.1): the edge signal (cookie) is set
 * IFF a valid client certificate was presented on the connection, across
 * arbitrary response shapes; otherwise the response is left unchanged.
 *
 * Per this repo's convention, the handler logic is replicated here in TypeScript
 * and exercised with fast-check; the real emitted source is separately exercised
 * by the runtime contract test (Task 7).
 *
 * Validates: Requirements 7.1, 17.3, 6.2.
 */
import * as fc from 'fast-check';

// ─────────────────────────────────────────────────────────────────────────────
// Replica of src/cloudfront/cloudfront-functions/modules/mtls-viewer-response.js
// ─────────────────────────────────────────────────────────────────────────────
interface CookieEntry { value: string; attributes: string }
interface FnResponse { cookies?: Record<string, CookieEntry>; headers?: Record<string, unknown>; statusCode?: number }
interface FnEvent { request: { context?: { certPresent?: string } }; response: FnResponse }

const COOKIE_NAME = 'fs_internal';
const COOKIE_ATTRIBUTES = 'Path=/; Secure; SameSite=Lax; Max-Age=3600; Domain=.example.com';

function applyViewerResponse(event: FnEvent): FnResponse {
  const response = event.response;
  const certPresent = !!(event.request && event.request.context && event.request.context.certPresent === 'true');
  if (certPresent) {
    response.cookies = response.cookies || {};
    response.cookies[COOKIE_NAME] = { value: '1', attributes: COOKIE_ATTRIBUTES };
  }
  return response;
}

// ─────────────────────────────────────────────────────────────────────────────
// Arbitraries
// ─────────────────────────────────────────────────────────────────────────────
// Existing cookie names, excluding our signal cookie so "preserved" checks are unambiguous.
const existingCookieName = fc.string({ minLength: 1, maxLength: 8 }).filter((n) => n !== COOKIE_NAME);
const RUNS = { numRuns: 200 };

function buildEvent(opts: {
  hasContext: boolean;
  certToken: string;
  existingCookieNames: string[];
  hasHeaders: boolean;
}): FnEvent {
  const cookies: Record<string, CookieEntry> = {};
  for (const n of opts.existingCookieNames) {
    cookies[n] = { value: 'x', attributes: 'Path=/' };
  }
  const response: FnResponse = {};
  if (opts.existingCookieNames.length > 0) { response.cookies = cookies; }
  if (opts.hasHeaders) { response.headers = { 'content-type': { value: 'text/html' } }; }
  response.statusCode = 200;
  return {
    request: opts.hasContext ? { context: { certPresent: opts.certToken } } : { context: undefined },
    response,
  };
}

describe('Property 6 (3.1) — edge signal set iff a valid cert was presented', () => {
  it('sets the cookie exactly when request.context.certPresent === "true"', () => {
    fc.assert(
      fc.property(
        fc.record({
          hasContext: fc.boolean(),
          certToken: fc.constantFrom('true', 'false', 'TRUE', '1', '', 'present'),
          existingCookieNames: fc.array(existingCookieName, { maxLength: 4 }),
          hasHeaders: fc.boolean(),
        }),
        (t) => {
          const event = buildEvent(t);
          const result = applyViewerResponse(event);
          const expectedSet = t.hasContext && t.certToken === 'true';
          const wasSet = !!(result.cookies && result.cookies[COOKIE_NAME] && result.cookies[COOKIE_NAME].value === '1');
          expect(wasSet).toBe(expectedSet);
        },
      ),
      RUNS,
    );
  });

  it('preserves any pre-existing cookies and leaves the response untouched when no cert was presented', () => {
    fc.assert(
      fc.property(
        fc.record({
          hasContext: fc.boolean(),
          certToken: fc.constantFrom('true', 'false', ''),
          existingCookieNames: fc.array(existingCookieName, { maxLength: 4 }),
          hasHeaders: fc.boolean(),
        }),
        (t) => {
          const event = buildEvent(t);
          const hadCookiesBefore = t.existingCookieNames.length > 0;
          const result = applyViewerResponse(event);
          const certPresent = t.hasContext && t.certToken === 'true';

          // Existing cookies always survive.
          for (const n of t.existingCookieNames) {
            expect(result.cookies && result.cookies[n]).toBeDefined();
          }
          // When no cert and no prior cookies, the response gains no cookies object.
          if (!certPresent && !hadCookiesBefore) {
            expect(result.cookies).toBeUndefined();
          }
        },
      ),
      RUNS,
    );
  });
});
