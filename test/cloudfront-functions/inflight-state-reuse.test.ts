import { createHash } from 'crypto';
import { FunctionComposer } from '../../src/cloudfront/cloudfront-functions/function-composer';
import { Extension } from '../../src/cloudfront/patterns/securedCloudFront';
import { createCloudFrontEvent } from '../fixtures/cloudfront-event';
import { TEST_SECRET } from '../helpers/jwt-factory';
import { createKvsMock } from '../mocks/kvs-mock';

/**
 * Guards the fix for #1516: the admin auth gate must NOT mint fresh PKCE state
 * (oauth_state / code_verifier) on a redirect when a sign-in is already in
 * flight. A non-navigation request provoked mid-sign-in (e.g. the dashboard's
 * 60s notification poll on the shared cookie domain) used to overwrite the
 * state the in-flight sign-in carried, so the callback's strict compare failed
 * with "400 Invalid state parameter". The gate must instead reuse the in-flight
 * state + verifier and set no cookies.
 */
function createAzureHandler() {
  const composer = new FunctionComposer();
  let code = composer.compose([Extension.REQUIRE_AUTH], undefined, {
    tenantId: 'test-tenant',
    clientId: 'test-client',
    redirectUri: 'https://example.com/oauth2/callback',
    cookieDomain: '.example.com',
    enableHeaderInjection: false,
    enableRefresh: false,
  });

  const kvsMock = createKvsMock({ initialData: { 'jwt.secret': TEST_SECRET } });

  code = code.replace(/import cf from 'cloudfront';\s*/g, '');
  code = code.replace(/const kvsHandle = cf\.kvs\(\);\s*/g, '');
  code = code.replace(/var crypto = require\('crypto'\);\s*/g, '');

  const wrappedCode = `
    const kvsHandle = kvsHandle_;
    const crypto = require('crypto');
    const atob = (str) => Buffer.from(str, 'base64').toString('binary');
    const btoa = (str) => Buffer.from(str, 'binary').toString('base64');
    ${code}
    return handler;
  `;

  const handlerFactory = new Function('kvsHandle_', 'require', wrappedCode);
  return handlerFactory(kvsMock, require) as (e: any) => Promise<any>;
}

/** Mirror auth-check.js generateState so the fixture state is well-formed/decodable. */
function makeState(path: string, host: string): string {
  const randomPart = Math.random().toString(36).substring(2) + Date.now().toString(36);
  return Buffer.from(JSON.stringify({ r: randomPart, p: path, h: host }))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/** Mirror auth-check.js generateCodeChallenge = base64url(SHA256(verifier)). */
function challengeOf(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

const INFLIGHT_VERIFIER = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-._~aBcD';

describe('#1516: in-flight PKCE state is reused, not clobbered', () => {
  it('redirect reuses an in-flight oauth_state + code_verifier and sets NO cookies', async () => {
    const handler = createAzureHandler();
    const state = makeState('/orders', 'example.com');

    // Unauthenticated request (no session cookie) that DOES carry a live flow.
    const event = createCloudFrontEvent({
      uri: '/orders',
      headers: { host: { value: 'example.com' } },
      cookies: {
        oauth_state: { value: state },
        code_verifier: { value: INFLIGHT_VERIFIER },
      },
    });

    const result = await handler(event);

    expect(result.statusCode).toBe(302);
    // Reuses the existing state — does not overwrite it.
    expect(result.headers.location.value).toContain('state=' + encodeURIComponent(state));
    // Challenge is re-derived from the stored verifier, so the callback's PKCE
    // exchange stays consistent with the in-flight flow.
    expect(result.headers.location.value).toContain(
      'code_challenge=' + encodeURIComponent(challengeOf(INFLIGHT_VERIFIER)),
    );
    // Critically: no Set-Cookie, so the live flow is untouched.
    expect(result.cookies).toBeUndefined();
  });

  it('three successive redirects leave the in-flight state unchanged', async () => {
    const handler = createAzureHandler();
    const state = makeState('/orders', 'example.com');
    const cookies = {
      oauth_state: { value: state },
      code_verifier: { value: INFLIGHT_VERIFIER },
    };

    for (let i = 0; i < 3; i++) {
      const result = await handler(
        createCloudFrontEvent({ uri: '/notifications', headers: { host: { value: 'example.com' } }, cookies }),
      );
      expect(result.statusCode).toBe(302);
      expect(result.headers.location.value).toContain('state=' + encodeURIComponent(state));
      expect(result.cookies).toBeUndefined();
    }
  });

  it('still mints a fresh flow when no in-flight cookies are present', async () => {
    const handler = createAzureHandler();
    const event = createCloudFrontEvent({ uri: '/orders', headers: { host: { value: 'example.com' } } });

    const result = await handler(event);

    expect(result.statusCode).toBe(302);
    expect(result.cookies).toBeDefined();
    expect(result.cookies.oauth_state.value).toBeTruthy();
    expect(result.cookies.code_verifier.value).toBeTruthy();
    expect(result.cookies.oauth_state.attributes).toContain('Max-Age=600');
  });

  it('mints fresh when only one of the pair is present (incomplete/torn flow)', async () => {
    const handler = createAzureHandler();
    const event = createCloudFrontEvent({
      uri: '/orders',
      headers: { host: { value: 'example.com' } },
      cookies: { oauth_state: { value: makeState('/orders', 'example.com') } }, // verifier missing
    });

    const result = await handler(event);

    expect(result.statusCode).toBe(302);
    expect(result.cookies).toBeDefined();
    expect(result.cookies.code_verifier.value).toBeTruthy();
  });

  it('mints fresh when oauth_state is malformed (undecodable)', async () => {
    const handler = createAzureHandler();
    const event = createCloudFrontEvent({
      uri: '/orders',
      headers: { host: { value: 'example.com' } },
      cookies: {
        oauth_state: { value: 'not-a-valid-base64url-json-@@@' },
        code_verifier: { value: INFLIGHT_VERIFIER },
      },
    });

    const result = await handler(event);

    expect(result.statusCode).toBe(302);
    expect(result.cookies).toBeDefined(); // fell through to minting
  });
});
