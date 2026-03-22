// tls-enforcer.js - CloudFront Function (viewer-request)
// Enforces TLS 1.3 with strongest ciphers only
// Requires: CloudFront-Viewer-TLS header in Origin Request Policy

function handler(event) {
  var request = event.request;
  var headers = request.headers;
  
  // Get TLS info from CloudFront-Viewer-TLS header
  // Format: TLSv1.3:TLS_AES_128_GCM_SHA256:sessionResumed
  var tlsInfo = headers['cloudfront-viewer-tls'] 
    ? headers['cloudfront-viewer-tls'].value 
    : '';
  
  // Parse TLS version and cipher
  var parts = tlsInfo.split(':');
  var tlsVersion = parts[0] || 'unknown';
  var cipher = parts[1] || 'unknown';
  
  // Check if using TLS 1.3
  if (!tlsVersion.startsWith('TLSv1.3')) {
    // Redirect to upgrade page with Request ID for incident tracking
    var requestId = event.context.requestId;
    return {
      statusCode: 302,
      statusDescription: 'Found',
      headers: {
        'location': { value: '/upgrade.html?ref=' + requestId },
        'cache-control': { value: 'no-store' },
      },
    };
  }
  
  // Verify strong cipher (TLS 1.3 GCM only)
  var allowedCiphers = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384'
  ];
  
  if (allowedCiphers.indexOf(cipher) === -1) {
    // Redirect to upgrade page with Request ID for incident tracking
    var requestId = event.context.requestId;
    return {
      statusCode: 302,
      statusDescription: 'Found',
      headers: {
        'location': { value: '/upgrade.html?ref=' + requestId },
        'cache-control': { value: 'no-store' },
      },
    };
  }
  
  // Allow request to proceed
  return request;
}
