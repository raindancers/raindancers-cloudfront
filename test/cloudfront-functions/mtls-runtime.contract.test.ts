import { buildConnectionFunctionCode, buildViewerResponseCode } from '../../src/cloudfront/patterns/viewer-mtls-access';

/**
 * Contract test (Task 7): drives the ACTUAL generated CloudFront JS 2.0 source
 * (connection function + viewer-response function) through a sandbox that mimics
 * the runtime, with a representative handshake/response event, and asserts the
 * allow / deny / cookie output. We do not own how CloudFront consumes the
 * function, so we exercise the emitted source verbatim rather than a replica.
 *
 * Validates: Requirements 3.5, 6.1, 7.1.
 */

// ── cf runtime mock ─────────────────────────────────────────────────────────
function makeKvs(keys: string[]) {
  const set = new Set(keys);
  return { exists: async (k: string) => set.has(k) };
}

function buildConnectionHandler(opts: {
  mode: 'Required' | 'Optional' | 'Passthrough';
  minAssurance: 'software' | 'hardware';
  propertyId?: string;
  revoked?: string[];
  granted?: string[];
}) {
  const code = buildConnectionFunctionCode({
    mode: opts.mode,
    minAssurance: opts.minAssurance,
    propertyId: opts.propertyId ?? '',
    revocationKvsId: 'REV',
    grantKvsId: 'GR',
  }).replace(/import cf from 'cloudfront';\s*/g, '');

  const capturedContext: Array<Record<string, string>> = [];
  const cfMock = {
    kvs: (id: string) => {
      if (id === 'REV') { return makeKvs(opts.revoked ?? []); }
      if (id === 'GR') { return makeKvs(opts.granted ?? []); }
      throw new Error(`unexpected kvs id ${id}`);
    },
    updateRequestContext: (ctx: Record<string, string>) => { capturedContext.push(ctx); },
  };

  // eslint-disable-next-line no-new-func
  const handler = new Function('cf', `${code}\nreturn handler;`)(cfMock) as (e: any) => Promise<any>;
  return { handler, context: () => capturedContext };
}

function connEvent(cert?: { serialNumber: string; san?: string[] }) {
  return { request: { clientCertificate: cert } };
}

const softwareCert = { serialNumber: 'AB12', san: ['urn:functionalself:assurance:software'] };
const hardwareCert = { serialNumber: 'CD34', san: ['urn:functionalself:assurance:hardware'] };

describe('Connection Function contract (generated source)', () => {
  it('Required + software: valid, non-revoked, in-assurance cert is allowed', async () => {
    const { handler } = buildConnectionHandler({ mode: 'Required', minAssurance: 'software' });
    await expect(handler(connEvent(softwareCert))).resolves.toEqual(connEvent(softwareCert).request);
  });

  it('Required: no cert is denied', async () => {
    const { handler } = buildConnectionHandler({ mode: 'Required', minAssurance: 'software' });
    await expect(handler(connEvent(undefined))).rejects.toThrow('mtls-deny');
  });

  it('Required + hardware: a software-assurance cert is denied (below min)', async () => {
    const { handler } = buildConnectionHandler({ mode: 'Required', minAssurance: 'hardware' });
    await expect(handler(connEvent(softwareCert))).rejects.toThrow('mtls-deny');
    // hardware cert clears the same gate
    const hw = buildConnectionHandler({ mode: 'Required', minAssurance: 'hardware' });
    await expect(hw.handler(connEvent(hardwareCert))).resolves.toBeDefined();
  });

  it('Required: a revoked serial is denied', async () => {
    const { handler } = buildConnectionHandler({ mode: 'Required', minAssurance: 'software', revoked: ['AB12'] });
    await expect(handler(connEvent(softwareCert))).rejects.toThrow('mtls-deny');
  });

  it('Required + per-property authz: denied without a grant, allowed with one', async () => {
    const denied = buildConnectionHandler({ mode: 'Required', minAssurance: 'software', propertyId: 'prop1' });
    await expect(denied.handler(connEvent(softwareCert))).rejects.toThrow('mtls-deny');

    const allowed = buildConnectionHandler({
      mode: 'Required', minAssurance: 'software', propertyId: 'prop1', granted: ['prop1:AB12'],
    });
    await expect(allowed.handler(connEvent(softwareCert))).resolves.toBeDefined();
  });

  it('Optional: never denies and records certPresent on the request context', async () => {
    const withCert = buildConnectionHandler({ mode: 'Optional', minAssurance: 'software' });
    await expect(withCert.handler(connEvent(softwareCert))).resolves.toBeDefined();
    expect(withCert.context()).toEqual([{ certPresent: 'true' }]);

    const noCert = buildConnectionHandler({ mode: 'Optional', minAssurance: 'software' });
    await expect(noCert.handler(connEvent(undefined))).resolves.toBeDefined();
    expect(noCert.context()).toEqual([{ certPresent: 'false' }]);
  });
});

// ── viewer-response ──────────────────────────────────────────────────────────
function buildViewerResponseHandler(cookieName: string, cookieAttributes: string) {
  const code = buildViewerResponseCode({ cookieName, cookieAttributes });
  // eslint-disable-next-line no-new-func
  return new Function(`${code}\nreturn handler;`)() as (e: any) => any;
}

describe('Viewer-response Function contract (generated source)', () => {
  const COOKIE = 'fs_internal';
  const ATTRS = 'Path=/; Secure; SameSite=Lax; Max-Age=3600; Domain=.example.com';

  it('sets the cookie when certPresent === "true"', () => {
    const handler = buildViewerResponseHandler(COOKIE, ATTRS);
    const response = handler({ request: { context: { certPresent: 'true' } }, response: { statusCode: 200 } });
    expect(response.cookies[COOKIE]).toEqual({ value: '1', attributes: ATTRS });
  });

  it('leaves the response untouched when no cert was presented', () => {
    const handler = buildViewerResponseHandler(COOKIE, ATTRS);
    const r1 = handler({ request: { context: { certPresent: 'false' } }, response: { statusCode: 200 } });
    expect(r1.cookies).toBeUndefined();
    const r2 = handler({ request: { context: undefined }, response: { statusCode: 200 } });
    expect(r2.cookies).toBeUndefined();
  });
});
