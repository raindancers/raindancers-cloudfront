import { FunctionComposer } from '../../src/cloudfront/cloudfront-functions/function-composer';
import { Extension } from '../../src/cloudfront/patterns/securedCloudFront';
import { createCloudFrontEvent, createAuthenticatedEvent } from '../fixtures/cloudfront-event';
import { signJwt } from '../helpers/hmac';
import { TEST_SECRET, createValidToken } from '../helpers/jwt-factory';
import { createKvsMock } from '../mocks/kvs-mock';

/**
 * Helper to evaluate composed CloudFront Function code in a sandboxed context.
 *
 * Creates a mock environment with KVS and crypto, evaluates the composed code,
 * and returns the handler function for testing.
 */
function createHandler(composerConfig: Record<string, unknown> = {}) {
  const composer = new FunctionComposer();
  let code = composer.compose([Extension.REQUIRE_AUTH], undefined, {
    tenantId: 'test-tenant',
    clientId: 'test-client',
    redirectUri: 'https://example.com/oauth2/callback',
    cookieDomain: '.example.com',
    enableHeaderInjection: true,
    headerInjectionClaims: { 'x-customer-id': 'customer_id', 'x-customer-email': 'email' },
    ...composerConfig,
  });

  // Create a sandboxed execution environment
  const kvsMock = createKvsMock({ initialData: { 'jwt.secret': TEST_SECRET } });

  // Strip the ES module import and replace with our mock binding
  code = code.replace(/import cf from 'cloudfront';\s*/g, '');
  code = code.replace(/const kvsHandle = cf\.kvs\(\);\s*/g, '');
  // Strip var crypto = require('crypto') since it's in the Node.js scope already
  code = code.replace(/var crypto = require\('crypto'\);\s*/g, '');

  // Build the function in a closure with mocked globals
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

describe('Header injection (Task 1.1)', () => {
  describe('stripping external headers', () => {
    it('strips x-customer-id from incoming request when header injection enabled', async () => {
      const { handler } = createHandler();
      const token = createValidToken();
      const event = createAuthenticatedEvent(token, {
        headers: {
          'host': { value: 'example.com' },
          'x-customer-id': { value: 'spoofed-id' },
        },
      });

      const result = await handler(event);

      // Should forward request (valid token), with x-customer-id set from JWT, not spoofed
      expect(result.headers['x-customer-id'].value).toBe('cust_abc123');
      expect(result.headers['x-customer-id'].value).not.toBe('spoofed-id');
    });

    it('strips x-customer-email from incoming request when header injection enabled', async () => {
      const { handler } = createHandler();
      const token = createValidToken();
      const event = createAuthenticatedEvent(token, {
        headers: {
          'host': { value: 'example.com' },
          'x-customer-email': { value: 'spoofed@evil.com' },
        },
      });

      const result = await handler(event);

      expect(result.headers['x-customer-email'].value).toBe('customer@example.com');
      expect(result.headers['x-customer-email'].value).not.toBe('spoofed@evil.com');
    });

    it('strips both identity headers even when no session cookie present', async () => {
      const { handler } = createHandler();
      const event = createCloudFrontEvent({
        uri: '/protected',
        headers: {
          'host': { value: 'example.com' },
          'x-customer-id': { value: 'spoofed' },
          'x-customer-email': { value: 'spoofed@evil.com' },
        },
      });

      const result = await handler(event);

      // Should redirect to auth (no session), and spoofed headers should not appear
      expect(result.statusCode).toBe(302);
    });
  });

  describe('injecting headers from JWT claims', () => {
    it('injects x-customer-id from JWT customer_id claim after validation', async () => {
      const { handler } = createHandler();
      const token = createValidToken({ customerId: 'cust_xyz789' });
      const event = createAuthenticatedEvent(token);

      const result = await handler(event);

      expect(result.headers['x-customer-id'].value).toBe('cust_xyz789');
    });

    it('injects x-customer-email from JWT email claim after validation', async () => {
      const { handler } = createHandler();
      const token = createValidToken({ email: 'alice@example.com' });
      const event = createAuthenticatedEvent(token);

      const result = await handler(event);

      expect(result.headers['x-customer-email'].value).toBe('alice@example.com');
    });

    it('does not inject header when claim is missing from JWT', async () => {
      const { handler } = createHandler();
      // Create a token without customer_id claim
      const claims = { sub: 'user-1', email: 'a@b.com', exp: Math.floor(Date.now() / 1000) + 3600, jti: 'sess_1' };
      const token = signJwt(claims, TEST_SECRET);
      const event = createAuthenticatedEvent(token);

      const result = await handler(event);

      expect(result.headers['x-customer-email'].value).toBe('a@b.com');
      expect(result.headers['x-customer-id']).toBeUndefined();
    });
  });

  describe('disabled header injection (backwards compatibility)', () => {
    it('does not strip or inject headers when header injection disabled', async () => {
      const { handler } = createHandler({ enableHeaderInjection: false, headerInjectionClaims: undefined });
      const token = createValidToken();
      const event = createAuthenticatedEvent(token, {
        headers: {
          'host': { value: 'example.com' },
          'x-customer-id': { value: 'external-value' },
        },
      });

      const result = await handler(event);

      // With injection disabled, external header should pass through untouched
      // (this is legacy behaviour — no stripping, no injection)
      expect(result.headers['x-customer-id'].value).toBe('external-value');
    });
  });
});
