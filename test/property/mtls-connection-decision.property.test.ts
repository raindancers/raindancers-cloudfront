/**
 * Property-Based Tests: ViewerMtlsAccess Connection Function decision logic.
 *
 * Feature: certIdentity. Validates the Req-3 / Req-8 conjunction enforced at the
 * CloudFront TLS handshake. Per this repo's convention, the decision logic is
 * replicated here in TypeScript and exercised with fast-check; the real emitted
 * source is separately exercised by the runtime contract test (Task 7).
 *
 * Covers Property 1 (2.1), Property 2 (2.2), Property 3 (2.3), Property 4 (2.4),
 * Property 5 (2.5), Property 10 (2.6), and the assurance-parser round-trip (2.7).
 *
 * Single typed `fc.record` arbitraries are used (not positional args) so the
 * callback parameters are concretely typed under both tsc and ts-jest.
 */
import * as fc from 'fast-check';

// ─────────────────────────────────────────────────────────────────────────────
// Replica of src/cloudfront/cloudfront-functions/modules/mtls-connection.js
// (kept behaviourally identical; the runtime contract test guards divergence).
// ─────────────────────────────────────────────────────────────────────────────
type Level = 'software' | 'hardware';
type Mode = 'Required' | 'Optional' | 'Passthrough';
const ASSURANCE_RANK: Record<Level, number> = { software: 1, hardware: 2 };

interface Cert {
  readonly serialNumber: string;
  readonly san: string[];
}

function parseAssurance(san: string[] | undefined): Level | null {
  for (const uri of san || []) {
    const m = /^urn:functionalself:assurance:(software|hardware)$/.exec(uri);
    if (m) {
      return m[1] as Level;
    }
  }
  return null;
}

interface DecideInput {
  readonly mode: Mode;
  readonly minAssurance: Level;
  /** '' when per-property authz is off. */
  readonly propertyId: string;
  readonly cert: Cert | null;
  readonly revokedSerials: ReadonlySet<string>;
  readonly grantMarkers: ReadonlySet<string>;
}

function decide(i: DecideInput): 'allow' | 'deny' {
  const cert = i.cert;
  const certPresent = !!cert;

  if (i.mode === 'Optional' || i.mode === 'Passthrough') {
    return 'allow'; // never denies (Req 6.1)
  }
  // Required mode
  if (!certPresent) {
    return 'deny';
  }
  const level = parseAssurance(cert!.san);
  if (!level || ASSURANCE_RANK[level] < ASSURANCE_RANK[i.minAssurance]) {
    return 'deny';
  }
  if (i.revokedSerials.has(cert!.serialNumber)) {
    return 'deny';
  }
  if (i.propertyId) {
    if (!i.grantMarkers.has(i.propertyId + ':' + cert!.serialNumber)) {
      return 'deny';
    }
  }
  return 'allow';
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers / arbitraries
// ─────────────────────────────────────────────────────────────────────────────
type SanChoice = 'software' | 'hardware' | 'none' | 'garbage';

function sanFor(choice: SanChoice): string[] {
  switch (choice) {
    case 'software': return ['urn:functionalself:assurance:software'];
    case 'hardware': return ['urn:functionalself:assurance:hardware'];
    case 'garbage': return ['urn:functionalself:assurance:admin', 'https://example.com'];
    case 'none': return [];
  }
}

/** Effective assurance rank of a SAN choice (0 = no recognised assurance). */
function rankOf(choice: SanChoice): number {
  return choice === 'software' ? 1 : choice === 'hardware' ? 2 : 0;
}

const serialArb = fc.string({ minLength: 2, maxLength: 12 });
const levelArb = fc.constantFrom('software', 'hardware');
const sanChoiceArb = fc.constantFrom('software', 'hardware', 'none', 'garbage');
const RUNS = { numRuns: 200 };

function setFor(present: boolean, key: string): Set<string> {
  const s = new Set<string>();
  if (present) { s.add(key); }
  return s;
}

describe('Property 1 (2.1) — Required-mode allow iff full conjunction holds', () => {
  it('allows exactly when present AND assurance>=min AND not-revoked AND (authz-off OR granted)', () => {
    fc.assert(
      fc.property(
        fc.record({
          serial: serialArb,
          sanChoice: sanChoiceArb,
          minAssurance: levelArb,
          present: fc.boolean(),
          revoked: fc.boolean(),
          authzOn: fc.boolean(),
          granted: fc.boolean(),
        }),
        (t) => {
          const cert: Cert | null = t.present ? { serialNumber: t.serial, san: sanFor(t.sanChoice) } : null;
          const expectedAllow =
            t.present &&
            rankOf(t.sanChoice) >= ASSURANCE_RANK[t.minAssurance] &&
            !t.revoked &&
            (!t.authzOn || t.granted);

          const result = decide({
            mode: 'Required',
            minAssurance: t.minAssurance,
            propertyId: t.authzOn ? 'prop-A' : '',
            cert,
            revokedSerials: setFor(t.revoked, t.serial),
            grantMarkers: setFor(t.granted, 'prop-A:' + t.serial),
          });
          expect(result === 'allow').toBe(expectedAllow);
        },
      ),
      RUNS,
    );
  });
});

describe('Property 2 (2.2) — assurance below minimum is always denied', () => {
  it('denies whenever effective assurance rank is below minAssurance (incl. no/garbage SAN)', () => {
    fc.assert(
      fc.property(
        fc.record({
          serial: serialArb,
          sanChoice: sanChoiceArb,
          minAssurance: levelArb,
          revoked: fc.boolean(),
          authzOn: fc.boolean(),
          granted: fc.boolean(),
        }),
        (t) => {
          fc.pre(rankOf(t.sanChoice) < ASSURANCE_RANK[t.minAssurance]);
          const result = decide({
            mode: 'Required',
            minAssurance: t.minAssurance,
            propertyId: t.authzOn ? 'prop-A' : '',
            cert: { serialNumber: t.serial, san: sanFor(t.sanChoice) },
            revokedSerials: setFor(t.revoked, t.serial),
            grantMarkers: setFor(t.granted, 'prop-A:' + t.serial),
          });
          expect(result).toBe('deny');
        },
      ),
      RUNS,
    );
  });
});

describe('Property 3 (2.3) — revoked serial is always denied', () => {
  it('denies a revoked serial regardless of assurance or grant', () => {
    fc.assert(
      fc.property(
        fc.record({
          serial: serialArb,
          certLevel: levelArb,
          minAssurance: levelArb,
          authzOn: fc.boolean(),
          granted: fc.boolean(),
        }),
        (t) => {
          const result = decide({
            mode: 'Required',
            minAssurance: t.minAssurance,
            propertyId: t.authzOn ? 'prop-A' : '',
            cert: { serialNumber: t.serial, san: sanFor(t.certLevel) },
            revokedSerials: setFor(true, t.serial), // always revoked
            grantMarkers: setFor(t.granted, 'prop-A:' + t.serial),
          });
          expect(result).toBe('deny');
        },
      ),
      RUNS,
    );
  });
});

describe('Property 4 (2.4) — missing per-property grant denies otherwise-valid certs', () => {
  it('denies a present, in-assurance, non-revoked cert when authz is on and no grant exists', () => {
    fc.assert(
      fc.property(
        fc.record({ serial: serialArb, certLevel: levelArb, minAssurance: levelArb }),
        (t) => {
          fc.pre(ASSURANCE_RANK[t.certLevel] >= ASSURANCE_RANK[t.minAssurance]);
          const result = decide({
            mode: 'Required',
            minAssurance: t.minAssurance,
            propertyId: 'prop-A',
            cert: { serialNumber: t.serial, san: sanFor(t.certLevel) },
            revokedSerials: new Set<string>(),
            grantMarkers: new Set<string>(), // no grant
          });
          expect(result).toBe('deny');
        },
      ),
      RUNS,
    );
  });
});

describe('Property 5 (2.5) — Optional/Passthrough mode never denies', () => {
  it('allows for cert present, absent, or invalid, in Optional and Passthrough', () => {
    fc.assert(
      fc.property(
        fc.record({
          mode: fc.constantFrom('Optional', 'Passthrough'),
          serial: serialArb,
          sanChoice: sanChoiceArb,
          minAssurance: levelArb,
          present: fc.boolean(),
          revoked: fc.boolean(),
        }),
        (t) => {
          const cert: Cert | null = t.present ? { serialNumber: t.serial, san: sanFor(t.sanChoice) } : null;
          const result = decide({
            mode: t.mode,
            minAssurance: t.minAssurance,
            propertyId: '',
            cert,
            revokedSerials: setFor(t.revoked, t.serial),
            grantMarkers: new Set<string>(),
          });
          expect(result).toBe('allow');
        },
      ),
      RUNS,
    );
  });
});

describe('Property 10 (2.6) — assurance is a gate, never sufficient alone', () => {
  it('denies when assurance is met but the cert is revoked or lacks a required grant', () => {
    fc.assert(
      fc.property(
        fc.record({ serial: serialArb, certLevel: levelArb, minAssurance: levelArb, revoked: fc.boolean() }),
        (t) => {
          fc.pre(ASSURANCE_RANK[t.certLevel] >= ASSURANCE_RANK[t.minAssurance]); // assurance satisfied
          const authzOn = !t.revoked; // when not revoked, use the grant gate as the disqualifier
          const result = decide({
            mode: 'Required',
            minAssurance: t.minAssurance,
            propertyId: authzOn ? 'prop-A' : '',
            cert: { serialNumber: t.serial, san: sanFor(t.certLevel) },
            revokedSerials: setFor(t.revoked, t.serial),
            grantMarkers: new Set<string>(), // no grant
          });
          expect(result).toBe('deny');
        },
      ),
      RUNS,
    );
  });
});

describe('Assurance parser round-trip (2.7)', () => {
  it('returns a level only for an exact urn:functionalself:assurance:(software|hardware) URI', () => {
    fc.assert(
      fc.property(fc.array(fc.string(), { maxLength: 5 }), (arbitrary) => {
        const parsed = parseAssurance(arbitrary);
        const hasSoftware = arbitrary.some((u) => u === 'urn:functionalself:assurance:software');
        const hasHardware = arbitrary.some((u) => u === 'urn:functionalself:assurance:hardware');
        if (!hasSoftware && !hasHardware) {
          expect(parsed).toBeNull();
        } else {
          expect(parsed === 'software' || parsed === 'hardware').toBe(true);
        }
      }),
      RUNS,
    );
  });

  it('rejects near-miss SAN URIs (wrong level, whitespace, case, prefix)', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          'urn:functionalself:assurance:admin',
          'urn:functionalself:assurance:hardware ',
          ' urn:functionalself:assurance:hardware',
          'urn:functionalself:assurance:HARDWARE',
          'urn:functionalself:assurance:',
          'https://functionalself/assurance/hardware',
        ),
        (badUri) => {
          expect(parseAssurance([badUri])).toBeNull();
        },
      ),
      RUNS,
    );
  });
});
