import * as fc from 'fast-check';
import { signJwt, verifyJwt, base64urlEncode, base64urlDecode } from './hmac';
import { TEST_SECRET, createValidToken, createExpiredToken, createTamperedToken } from './jwt-factory';

describe('HMAC helpers', () => {
  describe('signJwt / verifyJwt round-trip', () => {
    it('valid token verifies successfully and returns original claims', () => {
      const claims = { sub: 'user-1', email: 'test@example.com', exp: Math.floor(Date.now() / 1000) + 3600 };
      const token = signJwt(claims, TEST_SECRET);
      const result = verifyJwt(token, TEST_SECRET);

      expect(result).not.toBeNull();
      expect(result!.sub).toBe('user-1');
      expect(result!.email).toBe('test@example.com');
    });

    it('token signed with different secret fails verification', () => {
      const claims = { sub: 'user-1' };
      const token = signJwt(claims, 'secret-a');
      const result = verifyJwt(token, 'secret-b');

      expect(result).toBeNull();
    });

    it('malformed token (missing segment) returns null', () => {
      expect(verifyJwt('only.two', TEST_SECRET)).toBeNull();
      expect(verifyJwt('', TEST_SECRET)).toBeNull();
      expect(verifyJwt('a.b.c.d', TEST_SECRET)).toBeNull();
    });

    it('tampered payload returns null', () => {
      const token = signJwt({ sub: 'user-1' }, TEST_SECRET);
      const parts = token.split('.');
      // Modify the payload
      const tamperedPayload = base64urlEncode(JSON.stringify({ sub: 'attacker' }));
      const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      expect(verifyJwt(tamperedToken, TEST_SECRET)).toBeNull();
    });
  });

  describe('base64url encode/decode', () => {
    it('round-trips arbitrary strings', () => {
      const input = 'Hello, World! Special chars: +/= and unicode: 日本語';
      expect(base64urlDecode(base64urlEncode(input))).toBe(input);
    });

    it('produces URL-safe output (no +, /, or = characters)', () => {
      const encoded = base64urlEncode('test data with padding needs');
      expect(encoded).not.toMatch(/[+/=]/);
    });
  });

  describe('property: HMAC sign/verify round-trip preserves claims', () => {
    it('any claims object survives sign→verify unchanged', () => {
      fc.assert(
        fc.property(
          fc.record({
            sub: fc.string({ minLength: 1, maxLength: 100 }),
            email: fc.emailAddress(),
            customer_id: fc.string({ minLength: 1, maxLength: 50 }),
            exp: fc.integer({ min: 1000000000, max: 2000000000 }),
            iat: fc.integer({ min: 1000000000, max: 2000000000 }),
            jti: fc.uuid(),
          }),
          fc.string({ minLength: 16, maxLength: 64 }),
          (claims, secret) => {
            const token = signJwt(claims, secret);
            const result = verifyJwt(token, secret);
            expect(result).not.toBeNull();
            expect(result!.sub).toBe(claims.sub);
            expect(result!.email).toBe(claims.email);
            expect(result!.customer_id).toBe(claims.customer_id);
            expect(result!.exp).toBe(claims.exp);
            expect(result!.jti).toBe(claims.jti);
          },
        ),
        { numRuns: 200 },
      );
    });
  });
});

describe('JWT factory', () => {
  it('createValidToken produces a verifiable token', () => {
    const token = createValidToken();
    const result = verifyJwt(token, TEST_SECRET);
    expect(result).not.toBeNull();
    expect(result!.sub).toBe('entra-sub-12345');
    expect(result!.customer_id).toBe('cust_abc123');
  });

  it('createExpiredToken has exp in the past', () => {
    const token = createExpiredToken(120);
    const result = verifyJwt(token, TEST_SECRET);
    expect(result).not.toBeNull();
    const now = Math.floor(Date.now() / 1000);
    expect(result!.exp as number).toBeLessThan(now);
  });

  it('createTamperedToken fails verification with the standard secret', () => {
    const token = createTamperedToken();
    expect(verifyJwt(token, TEST_SECRET)).toBeNull();
  });
});
