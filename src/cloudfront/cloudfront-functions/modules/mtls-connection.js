// CloudFront Connection Function (JS 2.0) for ViewerMtlsAccess.
//
// Runs at the TLS handshake, AFTER CloudFront's standard PKI validation
// (chain, expiry, signature) and BEFORE the connection completes. No network
// access; may read only associated KeyValueStores; ~5 ms budget.
//
// The handshake event exposes leaf/intermediate certificate fields ONLY
// (serialNumber, issuer, subject, validity, sha256Fingerprint, ocspEndpoint,
// san, spki, sanHex). It does NOT expose policy OIDs or custom X.509 extensions,
// which is why assurance is encoded as a SAN URI the event can read.
//
// Placeholders are substituted at synth by buildConnectionFunctionCode():
//   __MODE__               Required | Optional | Passthrough
//   __MIN_ASSURANCE__      software | hardware
//   __PROPERTY_ID__        '' when per-property authz is off
//   __REVOCATION_KVS_ID__  id of the revocation KeyValueStore
//   __GRANT_KVS_ID__       id of the per-property allow-marker KeyValueStore ('' when authz off)
import cf from 'cloudfront';

var MODE = '__MODE__';
var MIN_ASSURANCE = '__MIN_ASSURANCE__';
var PROPERTY_ID = '__PROPERTY_ID__';
var ASSURANCE_RANK = { software: 1, hardware: 2 };

var revocationKvs = cf.kvs('__REVOCATION_KVS_ID__');
var grantKvs = PROPERTY_ID ? cf.kvs('__GRANT_KVS_ID__') : null;

function parseAssurance(san) {
  // san is an array of URIs; find urn:functionalself:assurance:<level>
  var list = san || [];
  for (var i = 0; i < list.length; i++) {
    var m = /^urn:functionalself:assurance:(software|hardware)$/.exec(list[i]);
    if (m) {
      return m[1];
    }
  }
  return null; // no SAN URI => below any minAssurance (Req 4.5)
}

function logDecision(cert, decision, certPresent) {
  // Surfaced to connection logs; exact logCustomData primitive follows the
  // final Connection Function API at deploy time. (Req 3.7, 22.4)
  console.log(JSON.stringify({
    serial: cert ? cert.serialNumber : null,
    decision: decision,
    certPresent: certPresent,
  }));
}

function deny(cert, reason) {
  logDecision(cert, 'deny:' + reason, true);
  throw new Error('mtls-deny');
}

async function handler(event) {
  var cert = event.request.clientCertificate; // present iff a cert was offered and PKI-valid
  var certPresent = !!cert;

  if (MODE === 'Optional' || MODE === 'Passthrough') {
    // Optional/Passthrough NEVER deny (Req 6.1). Record cert-present for the
    // edge signal consumed by the viewer-response function (Req 6.2, 6.3).
    cf.updateRequestContext({ certPresent: certPresent ? 'true' : 'false' });
    logDecision(cert, 'allow-optional', certPresent);
    return event.request;
  }

  // ---- Required mode (Req 3) ----
  if (!certPresent) {
    return deny(cert, 'no-cert'); // CloudFront already denies a missing chain; defensive
  }

  var level = parseAssurance(cert.san);
  if (!level || ASSURANCE_RANK[level] < ASSURANCE_RANK[MIN_ASSURANCE]) {
    // Assurance is a necessary gate, never sufficient alone (Req 3.3, 3.6, 4.5).
    return deny(cert, 'assurance-below-min');
  }

  var revoked = await revocationKvs.exists(cert.serialNumber);
  if (revoked) {
    return deny(cert, 'revoked'); // Req 3.4
  }

  if (grantKvs) {
    var granted = await grantKvs.exists(PROPERTY_ID + ':' + cert.serialNumber);
    if (!granted) {
      return deny(cert, 'no-property-grant'); // Req 8.1
    }
  }

  // Allow = (valid chain, by CloudFront) AND (assurance >= min) AND (not revoked)
  //         AND (per-property grant where configured). (Req 3.5, 3.7)
  logDecision(cert, 'allow', certPresent);
  return event.request;
}
