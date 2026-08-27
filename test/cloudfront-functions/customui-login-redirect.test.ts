import { FunctionComposer } from '../../src/cloudfront/cloudfront-functions/function-composer';
import { Extension } from '../../src/cloudfront/patterns/securedCloudFront';
import { createCloudFrontEvent, createAuthenticatedEvent } from '../fixtures/cloudfront-event';
import { signJwt } from '../helpers/hmac';
import { TEST_SECRET, createValidToken } from '../helpers/jwt-factory';
import { createKvsMock } from '../mocks/kvs-mock';

/**
 * Builds the composed edge function in CUSTOM-UI mode (loginRedirectPath set) and
 * returns a callable handler evaluated in a sandbox — the same harness used by the
 * existing header-injection contract test.
 */
function createHandler(composerConfig: Record<string, unknown> = {}) {
  const composer = new FunctionComposer();
  let code = composer.compose([Extension.REQUIRE_AUTH], undefined, {
    loginRedirectPath: '/login',
    enableHeaderInjection: true,
    headerInjectionClaims: { 'x-customer-id': 'customer_id', 'x-customer-email': 'email' },
    enableRefresh: true,
    ...composerConfig,
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
  const handler = new Function('kvsHandle_', 'require', wrappedCode)(kvsMock, require);
  return { handler: handler, kvs: kvsMock };
}

describe('Custom-UI edge auth', () => {
  describe('unauthenticated redirect goes to the first-party login page', () => {
    it('302s to /login?returnTo=<path> with no session cookie', async () => {
      const { handler } = createHandler();
      const event = createCloudFrontEvent({ uri: '/account', headers: { host: { value: 'shop.example.com' } } });

      const result = await handler(event);

      expect(result.statusCode).toBe(302);
      expect(result.headers.location.value).toBe('/login?returnTo=%2Faccount');
    });

    it('never redirects to a Cognito hosted UI or external IdP', async () => {
      const { handler } = createHandler();
      const event = createCloudFrontEvent({ uri: '/account' });

      const result = await handler(event);

      expect(result.headers.location.value).not.toContain('amazoncognito.com');
      expect(result.headers.location.value).not.toContain('/oauth2/authorize');
      expect(result.headers.location.value).not.toContain('login.microsoftonline.com');
    });

    it('does not set PKCE state/verifier cookies (SRP happens on the login page)', async () => {
      const { handler } = createHandler();
      const event = createCloudFrontEvent({ uri: '/account' });

      const result = await handler(event);

      expect(result.cookies).toBeUndefined();
    });

    it('preserves the original query string in returnTo', async () => {
      const { handler } = createHandler();
      const event = createCloudFrontEvent({ uri: '/account', querystring: { tab: { value: 'orders' } } });

      const result = await handler(event);

      expect(result.headers.location.value).toBe('/login?returnTo=%2Faccount%3Ftab%3Dorders');
    });
  });

  describe('authenticated requests pass through with injected identity headers', () => {
    it('injects x-customer-id / x-customer-email from validated claims', async () => {
      const { handler } = createHandler();
      const event = createAuthenticatedEvent(createValidToken({ customerId: 'cust_xyz789', email: 'alice@example.com' }));

      const result = await handler(event);

      expect(result.headers['x-customer-id'].value).toBe('cust_xyz789');
      expect(result.headers['x-customer-email'].value).toBe('alice@example.com');
    });

    it('strips spoofed identity headers before injecting from the JWT', async () => {
      const { handler } = createHandler();
      const event = createAuthenticatedEvent(createValidToken({ customerId: 'cust_real' }), {
        headers: { 'host': { value: 'shop.example.com' }, 'x-customer-id': { value: 'spoofed' } },
      });

      const result = await handler(event);

      expect(result.headers['x-customer-id'].value).toBe('cust_real');
    });
  });

  describe('revocation and refresh', () => {
    it('redirects a revoked session to /login', async () => {
      const { handler, kvs } = createHandler();
      const now = Math.floor(Date.now() / 1000);
      const token = signJwt({ sub: 'u1', email: 'a@b.com', customer_id: 'c1', jti: 'sess_revoked', exp: now + 3600 }, TEST_SECRET);
      kvs.set('revoked:sess_revoked', String(now));
      const event = createAuthenticatedEvent(token, { uri: '/account' });

      const result = await handler(event);

      expect(result.statusCode).toBe(302);
      expect(result.headers.location.value).toContain('/login?returnTo=');
    });

    it('sends an expired-but-valid session to the refresh endpoint', async () => {
      const { handler } = createHandler();
      const now = Math.floor(Date.now() / 1000);
      const token = signJwt({ sub: 'u1', email: 'a@b.com', customer_id: 'c1', jti: 'sess_old', exp: now - 60 }, TEST_SECRET);
      const event = createAuthenticatedEvent(token, { uri: '/account' });

      const result = await handler(event);

      expect(result.statusCode).toBe(302);
      expect(result.headers.location.value).toContain('/oauth2/refresh?return_to=');
    });
  });
});
