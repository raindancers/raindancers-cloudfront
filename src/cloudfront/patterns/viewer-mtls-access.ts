import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cloudfront as cloudfront,
  aws_s3 as s3,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

/**
 * Viewer mTLS enforcement mode applied at the CloudFront TLS handshake.
 *
 * - `Required`: every connection must present a client certificate that passes
 *   the Connection Function's checks, otherwise the handshake is denied.
 * - `Optional`: connections without a certificate are allowed; a presented
 *   certificate is validated and its presence recorded (never denied).
 * - `Passthrough`: CloudFront does not validate against a trust store; the
 *   certificate is forwarded to the origin for it to validate.
 */
export type ViewerMtlsMode = 'Required' | 'Optional' | 'Passthrough';

/** Assurance level carried by a client certificate (encoded as a SAN URI). */
export type AssuranceLevel = 'software' | 'hardware';

/**
 * Trust Store source. Provide EITHER a CA bundle in S3 (create mode) OR an
 * existing trust store id (attach mode). Supplying both fails synthesis.
 */
export interface TrustStoreConfig {
  /** Create a Trust Store from a CA bundle in S3. Mutually exclusive with existingTrustStoreId. (Req 2.1) */
  readonly caBundleBucket?: s3.IBucket;
  readonly caBundleKey?: string;
  /** Attach to an existing Trust Store. Mutually exclusive with the CA-bundle source. (Req 2.2, 2.3) */
  readonly existingTrustStoreId?: string;
  /** Default true. (Req 2.4) */
  readonly advertiseCaNames?: boolean;
  /** Default false. (Req 2.5) */
  readonly ignoreCertificateExpiry?: boolean;
}

/** Minimum assurance policy. The level is a necessary gate, never sufficient alone. */
export interface AssurancePolicy {
  /** Default 'software'. Necessary gate only — never sufficient alone. (Req 4.1, 4.2, 3.6) */
  readonly minAssurance?: AssuranceLevel;
}

/**
 * Per-property authorization. When supplied, an otherwise-valid certificate is
 * only allowed if a `"<propertyId>:<serial>"` allow-marker exists in the KVS.
 */
export interface PropertyAuthz {
  /** Property scope key component. (Req 8) */
  readonly propertyId: string;
  /** KVS holding allow-markers keyed "<propertyId>:<serial>". Written by the [id] registry. (Req 8.1) */
  readonly allowMarkerKvs: cloudfront.IKeyValueStore;
}

/**
 * Edge cert-present signal. When configured, a viewer-response function sets the
 * named cookie iff a valid certificate was presented on the connection. This is
 * a best-effort, client-readable signal (never HttpOnly), not a security control.
 */
export interface CertPresentSignal {
  /** Cookie name to set when a valid cert was presented (e.g. 'fs_internal'). (Req 7.3) */
  readonly cookieName: string;
  /** Cookie attributes emitted verbatim (Path, Secure, SameSite, Max-Age, Domain...). (Req 7.3, 18) */
  readonly cookieAttributes: string;
}

/**
 * Standards-aligned, overridable retention policy for revoked serials in the KVS.
 * The default retains a revoked serial until its own certificate expiry to bound
 * KVS growth. No certificate-lifetime value is hardcoded in this library. (Req 28.8, 28.11)
 */
export interface RevocationRetentionPolicy {
  /** Retain a revoked serial until its own certificate expiry (notAfter). Default true. (Req 28.8) */
  readonly retainUntilExpiry?: boolean;
  /**
   * Optional absolute safety bound on how long a revoked serial is retained.
   * Left undefined by default: no certificate-lifetime value is assumed here;
   * the consuming/identity side owns issuance lifetimes. (Req 28.11)
   */
  readonly maxRetention?: core.Duration;
}

/**
 * Props for {@link ViewerMtlsAccess}.
 *
 * Generic and props-driven: no project domain, stage, brand, or policy value is
 * hardcoded. All such values arrive from the caller. (Req 11.5)
 */
export interface ViewerMtlsAccessProps {
  /** Default 'Required'. (Req 1.1, 1.2) */
  readonly mode?: ViewerMtlsMode;
  readonly trustStore: TrustStoreConfig;
  readonly assurance?: AssurancePolicy;
  /** Omit => single-property: any valid, in-assurance, non-revoked cert authorised. (Req 8.2) */
  readonly propertyAuthz?: PropertyAuthz;
  /** Supply to reuse a KVS; omit to have the construct create one. (Req 5.1, 5.2) */
  readonly revocationStore?: cloudfront.IKeyValueStore;
  /** Omit => no viewer-response function synthesised. (Req 7.1, 7.2) */
  readonly certPresentSignal?: CertPresentSignal;
  /** Default false. (Req 9) */
  readonly forwardCertHeadersToOrigin?: boolean;
  /**
   * Standards-aligned overridable default only (Req 28.11): revoked serials are
   * retained in the KVS until their own expiry to bound growth (Req 28.8).
   * No certificate-lifetime value is hardcoded in this library.
   */
  readonly revocationRetention?: RevocationRetentionPolicy;
}

/** Inputs for {@link buildConnectionFunctionCode}. */
export interface ConnectionFunctionCodeOptions {
  readonly mode: ViewerMtlsMode;
  readonly minAssurance: AssuranceLevel;
  /** '' when per-property authz is off. */
  readonly propertyId: string;
  readonly revocationKvsId: string;
  /** '' when per-property authz is off. */
  readonly grantKvsId: string;
}

/**
 * Reads the JS 2.0 Connection Function source and substitutes the synth-time
 * placeholders, producing the deployable function code. Kept as a pure exported
 * helper so it can be unit-tested and reused by {@link ViewerMtlsAccess}.
 */
export function buildConnectionFunctionCode(opts: ConnectionFunctionCodeOptions): string {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'cloudfront-functions', 'modules', 'mtls-connection.js'),
    'utf-8',
  );
  return source
    .replace(/__MODE__/g, opts.mode)
    .replace(/__MIN_ASSURANCE__/g, opts.minAssurance)
    .replace(/__PROPERTY_ID__/g, opts.propertyId)
    .replace(/__REVOCATION_KVS_ID__/g, opts.revocationKvsId)
    .replace(/__GRANT_KVS_ID__/g, opts.grantKvsId);
}

/** Inputs for {@link buildViewerResponseCode}. */
export interface ViewerResponseCodeOptions {
  readonly cookieName: string;
  /** Verbatim cookie attributes (e.g. 'Path=/; Secure; SameSite=Lax; Max-Age=3600; Domain=.example.com'). */
  readonly cookieAttributes: string;
}

/**
 * Reads the JS 2.0 viewer-response function source and substitutes the cookie
 * name/attributes. Synthesised only when a {@link CertPresentSignal} is configured.
 */
export function buildViewerResponseCode(opts: ViewerResponseCodeOptions): string {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'cloudfront-functions', 'modules', 'mtls-viewer-response.js'),
    'utf-8',
  );
  return source
    .replace(/__COOKIE_NAME__/g, opts.cookieName)
    .replace(/__COOKIE_ATTRIBUTES__/g, opts.cookieAttributes);
}

/**
 * `ViewerMtlsAccess` enforces (or detects) CloudFront viewer mTLS at the TLS
 * handshake via a distribution-level Connection Function. It is attach-only: it
 * composes with a caller-supplied distribution and never adds a viewer-request
 * function, so it does not collide with any existing per-behaviour function.
 *
 * This is a generic, reusable building block. All project-specific values arrive
 * via props; nothing is hardcoded here. (Req 11.5)
 */
export class ViewerMtlsAccess extends constructs.Construct {
  /** Resolved viewer mTLS mode (default 'Required'). */
  public readonly mode: ViewerMtlsMode;
  /** Resolved minimum assurance level (default 'software'). */
  public readonly minAssurance: AssuranceLevel;
  /** Resolved trust-store CA-name advertisement (default true). */
  public readonly advertiseCaNames: boolean;
  /** Resolved certificate-expiry handling (default false). */
  public readonly ignoreCertificateExpiry: boolean;
  /** Resolved cert-header forwarding to origin (default false). */
  public readonly forwardCertHeadersToOrigin: boolean;

  /** Resolved revocation retention policy (retain revoked serials until expiry by default). */
  public readonly revocationRetention: RevocationRetentionPolicy;
  /** Id of the associated Trust Store (created from a CA bundle, or attached). (Req 11.1) */
  public readonly trustStoreId: string;
  /** The handshake Connection Function. (Req 11.2) */
  public readonly connectionFunction: cloudfront.CfnConnectionFunction;
  /** Revocation KeyValueStore (created or supplied); external systems populate revoked serials here. (Req 5.3, 11.3) */
  public readonly revocationStore: cloudfront.IKeyValueStore;
  /** Viewer-response edge-signal function; present only when `certPresentSignal` is configured. (Req 7, 11.4) */
  public readonly viewerResponseFunction?: cloudfront.Function;

  constructor(scope: constructs.Construct, id: string, props: ViewerMtlsAccessProps) {
    super(scope, id);

    this.mode = props.mode ?? 'Required';
    this.minAssurance = props.assurance?.minAssurance ?? 'software';
    this.advertiseCaNames = props.trustStore.advertiseCaNames ?? true;
    this.ignoreCertificateExpiry = props.trustStore.ignoreCertificateExpiry ?? false;
    this.forwardCertHeadersToOrigin = props.forwardCertHeadersToOrigin ?? false;
    this.revocationRetention = {
      retainUntilExpiry: props.revocationRetention?.retainUntilExpiry ?? true,
      maxRetention: props.revocationRetention?.maxRetention,
    };

    const nameBase = core.Names.uniqueResourceName(this, { maxLength: 48 });

    // ---- Task 4: Trust Store (create from CA bundle OR attach to existing; mutually exclusive) ----
    const ts = props.trustStore;
    const hasBundle = !!(ts.caBundleBucket || ts.caBundleKey);
    const hasExisting = !!ts.existingTrustStoreId;
    if (hasBundle && hasExisting) {
      throw new Error(
        'ViewerMtlsAccess: trustStore must provide EITHER a CA-bundle source (caBundleBucket + caBundleKey) OR existingTrustStoreId, not both (Req 2.3).',
      );
    }
    if (hasExisting) {
      this.trustStoreId = ts.existingTrustStoreId!;
    } else if (ts.caBundleBucket && ts.caBundleKey) {
      const trustStore = new cloudfront.CfnTrustStore(this, 'TrustStore', {
        name: `${nameBase}Ts`,
        caCertificatesBundleSource: {
          caCertificatesBundleS3Location: {
            bucket: ts.caBundleBucket.bucketName,
            key: ts.caBundleKey,
            region: core.Stack.of(this).region,
          },
        },
      });
      this.trustStoreId = trustStore.attrId;
    } else {
      throw new Error(
        'ViewerMtlsAccess: trustStore requires either caBundleBucket + caBundleKey (create) or existingTrustStoreId (attach) (Req 2.1, 2.2).',
      );
    }

    // ---- Task 5: Revocation KVS (create or accept) ----
    this.revocationStore = props.revocationStore ?? new cloudfront.KeyValueStore(this, 'RevocationStore');
    const grantKvs = props.propertyAuthz?.allowMarkerKvs;

    // ---- Task 2 wiring: Connection Function ----
    const keyValueStoreAssociations: cloudfront.CfnConnectionFunction.KeyValueStoreAssociationProperty[] = [
      { keyValueStoreArn: this.revocationStore.keyValueStoreArn },
    ];
    if (grantKvs) {
      keyValueStoreAssociations.push({ keyValueStoreArn: grantKvs.keyValueStoreArn });
    }
    this.connectionFunction = new cloudfront.CfnConnectionFunction(this, 'ConnectionFunction', {
      name: `${nameBase}Cf`,
      autoPublish: true,
      connectionFunctionCode: buildConnectionFunctionCode({
        mode: this.mode,
        minAssurance: this.minAssurance,
        propertyId: props.propertyAuthz?.propertyId ?? '',
        revocationKvsId: this.revocationStore.keyValueStoreId,
        grantKvsId: grantKvs?.keyValueStoreId ?? '',
      }),
      connectionFunctionConfig: {
        comment: 'ViewerMtlsAccess handshake decision function',
        runtime: 'cloudfront-js-2.0',
        keyValueStoreAssociations,
      },
    });

    // ---- Task 3 wiring: viewer-response edge-signal function (only if configured) ----
    if (props.certPresentSignal) {
      this.viewerResponseFunction = new cloudfront.Function(this, 'ViewerResponse', {
        comment: 'ViewerMtlsAccess cert-present edge signal',
        runtime: cloudfront.FunctionRuntime.JS_2_0,
        code: cloudfront.FunctionCode.fromInline(buildViewerResponseCode({
          cookieName: props.certPresentSignal.cookieName,
          cookieAttributes: props.certPresentSignal.cookieAttributes,
        })),
      });
    }
  }

  /**
   * Attach viewer mTLS to a caller-supplied existing distribution (attach-only, Req 11.6).
   *
   * Sets `viewerMtlsConfig` and the distribution-level connection-function
   * association via L1 overrides, appends the viewer-response signal function
   * (when configured) without disturbing any existing per-behaviour functions,
   * and hard-fails synthesis if the distribution is not HTTPS-only (Req 10).
   */
  public attachToDistribution(distribution: cloudfront.IDistribution): void {
    const cfnDist = distribution.node.tryFindChild('Resource') as cloudfront.CfnDistribution | undefined;
    if (!cfnDist) {
      throw new Error('ViewerMtlsAccess.attachToDistribution: could not locate the CfnDistribution (node child "Resource").');
    }

    // HTTPS-only hard-fail (Req 10 / SC-4): every behaviour must be https-only.
    const config: any = core.Stack.of(cfnDist).resolve(cfnDist.distributionConfig);
    const behaviours: any[] = [config?.defaultCacheBehavior, ...(config?.cacheBehaviors ?? [])].filter(Boolean);
    if (behaviours.length === 0) {
      throw new Error('ViewerMtlsAccess.attachToDistribution: unable to read the distribution viewer protocol policy to enforce HTTPS-only (Req 10).');
    }
    for (const b of behaviours) {
      if (b.viewerProtocolPolicy !== 'https-only') {
        throw new Error(
          `ViewerMtlsAccess.attachToDistribution: viewer mTLS requires an HTTPS-only distribution; found viewerProtocolPolicy "${b.viewerProtocolPolicy}". Set ViewerProtocolPolicy.HTTPS_ONLY on all behaviours (Req 10).`,
        );
      }
    }

    cfnDist.addPropertyOverride('DistributionConfig.ViewerMtlsConfig', {
      Mode: this.mode,
      TrustStoreConfig: {
        TrustStoreId: this.trustStoreId,
        AdvertiseTrustStoreCaNames: this.advertiseCaNames,
        IgnoreCertificateExpiry: this.ignoreCertificateExpiry,
      },
    });
    cfnDist.addPropertyOverride('DistributionConfig.ConnectionFunctionAssociation', {
      Id: this.connectionFunction.attrId,
    });

    // Append the viewer-response signal WITHOUT clobbering existing (e.g. viewer-request) associations.
    if (this.viewerResponseFunction) {
      const existing: any[] = (config?.defaultCacheBehavior?.functionAssociations ?? []) as any[];
      cfnDist.addPropertyOverride('DistributionConfig.DefaultCacheBehavior.FunctionAssociations', [
        ...existing,
        { EventType: 'viewer-response', FunctionARN: this.viewerResponseFunction.functionArn },
      ]);
    }
    // NOTE: forwardCertHeadersToOrigin is recorded but NOT auto-wired in v1: forwarding
    // CloudFront-Viewer-Cert-* headers requires an origin-request policy on the caller's
    // behaviours, which this attach-only construct will not clobber. Tracked as a follow-up.
  }
}
