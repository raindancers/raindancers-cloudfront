import { FunctionComposer } from '../../src/cloudfront/cloudfront-functions/function-composer';
import { Extension } from '../../src/cloudfront/patterns/securedCloudFront';
import { createAuthenticatedEvent } from '../fixtures/cloudfront-event';
import { TEST_SECRET, createValidToken, createExpiredToken, createTamperedToken } from '../helpers/jwt-factory';
import { createKvsMock } from '../mocks/kvs-mock';

/**
 * Create a handler with refresh enabled/disabled for testing.
 *
 * @param enableRefresh - Whether the refresh redirect is enabled
 * @returns The handler function and KVS mock
 */
function createHandler(enableRefresh: boolean) {
  const composer = new FunctionComposer();
  let code = composer.compose([Extension.REQUIRE_AUTH], undefined, {
    tenantId: 'test-tenant',
    clientId: 'test-client',
    redirectUri: 'https://example.com/oauth2/callback',
    cookieDomain: '.example.com',
    enableHeaderInjection: false,
    enableRefresh: enableRefresh,
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
  const handler = handlerFactory(kvsMock, require);

  return { handler: handler, kvs: kvsMock };
}

describe('Expired-JWT refresh redirect (Task 1.4)', () => {
  describe('refresh enabled', () => {
    it('expired JWT with valid HMAC redirects to /oauth2/refresh', async () => {
      const { handler } = createHandler(true);
      const token = createExpiredToken(120);
      const event = createAuthenticatedEvent(token, { uri: '/account' });

      const result = await handler(event);

      expect(result.statusCode).toBe(302);
      expect(result.headers.location.value).toContain('/oauth2/refresh?return_to=');
    });

    it('refresh redirect includes encoded return_to with original URL', async () => {
      const { handler } = createHandler(true);
      const token = createExpiredToken(60);
      const event = createAuthenticatedEvent(token, {
        uri: '/shop/products',
        headers: { host: { value: 'www.example.com' } },
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(302);
      const location = result.headers.location.value;
      expect(location).toContain('/oauth2/refresh?return_to=');
      const returnTo = decodeURIComponent(location.split('return_to=')[1]);
      expect(returnTo).toBe('https://www.example.com/shop/products');
    });

    it('refresh redirect does not set any cookies (preserves session cookie)', async () => {
      const { handler } = createHandler(true);
      const token = createExpiredToken(60);
      const event = createAuthenticatedEvent(token);

      const result = await handler(event);

      expect(result.statusCode).toBe(302);
      expect(result.cookies).toBeUndefined();
    });

    it('expired JWT with invalid HMAC redirects to Entra login (not refresh)', async () => {
      const { handler } = createHandler(true);
      const token = createTamperedToken({ exp: Math.floor(Date.now() / 1000) - 60 });
      const event = createAuthenticatedEvent(token);

      const result = await handler(event);

      // Invalid HMAC → redirect to Entra login, NOT refresh
      expect(result.statusCode).toBe(302);
      expect(result.headers.location.value).toContain('login.microsoftonline.com');
      expect(result.headers.location.value).not.toContain('/oauth2/refresh');
    });

    it('valid (non-expired) JWT passes through without redirect', async () => {
      const { handler } = createHandler(true);
      const token = createValidToken();
      const event = createAuthenticatedEvent(token);

      const result = await handler(event);

      // Should return the request object (pass-through), not a redirect
      expect(result.statusCode).toBeUndefined();
      expect(result.uri).toBeDefined();
    });
  });

  describe('refresh disabled (backwards compatibility)', () => {
    it('expired JWT with valid HMAC redirects to Entra login when refresh disabled', async () => {
      const { handler } = createHandler(false);
      const token = createExpiredToken(120);
      const event = createAuthenticatedEvent(token);

      const result = await handler(event);

      expect(result.statusCode).toBe(302);
      expect(result.headers.location.value).toContain('login.microsoftonline.com');
      expect(result.headers.location.value).not.toContain('/oauth2/refresh');
    });
  });
});
