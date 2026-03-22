// tls-check.js - TLS 1.3 enforcement check
// Returns null if check passes, or redirect response if fails

/**
 * Check if request uses TLS 1.3 with approved ciphers
 * @param {object} event - CloudFront event object
 * @returns {object|null} Redirect response or null if check passes
 */
function checkTLS(event) {
  var headers = event.request.headers;
  var requestId = event.context.requestId;
  
  // Get TLS info from CloudFront-Viewer-TLS header
  var tlsInfo = headers['cloudfront-viewer-tls'] 
    ? headers['cloudfront-viewer-tls'].value 
    : '';
  
  // Parse TLS version and cipher
  var parts = tlsInfo.split(':');
  var tlsVersion = parts[0] || 'unknown';
  var cipher = parts[1] || 'unknown';
  
  // Check if using TLS 1.3
  if (!tlsVersion.startsWith('TLSv1.3')) {
    return createRedirect('/upgrade.html', requestId);
  }
  
  // Verify strong cipher (TLS 1.3 GCM only)
  var allowedCiphers = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384'
  ];
  
  if (allowedCiphers.indexOf(cipher) === -1) {
    return createRedirect('/upgrade.html', requestId);
  }
  
  return null; // Check passed
}
