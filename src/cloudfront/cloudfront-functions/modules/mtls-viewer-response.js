// CloudFront viewer-response Function for ViewerMtlsAccess.
//
// Sets a first-party cookie IFF the connection presented a valid client
// certificate. "Cert present" is recorded on the request context by the
// Connection Function (cf.updateRequestContext({ certPresent })) at the
// handshake; this function reads it and, when true, stamps the cookie.
//
// Associated on the VIEWER-RESPONSE event only (a different event from the
// viewer-request slot that geodirector occupies), so there is no collision.
//
// The cookie is best-effort and client-readable (never HttpOnly) so client-side
// GA/GTM can read it; it is not a security control.
//
// Placeholders substituted at synth by buildViewerResponseCode():
//   __COOKIE_NAME__        cookie name (e.g. fs_internal)
//   __COOKIE_ATTRIBUTES__  verbatim cookie attributes (Path, Secure, SameSite, Max-Age, Domain)
function handler(event) {
  var response = event.response;
  var certPresent = event.request && event.request.context && event.request.context.certPresent === 'true';
  if (certPresent) {
    response.cookies = response.cookies || {};
    response.cookies['__COOKIE_NAME__'] = { value: '1', attributes: '__COOKIE_ATTRIBUTES__' };
  }
  return response; // response unchanged when no cert was presented
}
