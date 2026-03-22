// role-enforcer.js - CloudFront Function (viewer-request)
// Enforces role-based access control
// Requires: JWT in Authorization header (validated by auth-check.js)
// Requires: x-required-roles header set by construct

function handler(event) {
  var request = event.request;
  var headers = request.headers;
  
  // Get JWT from Authorization header
  var authHeader = headers['authorization'] ? headers['authorization'].value : '';
  if (!authHeader.startsWith('Bearer ')) {
    return {
      statusCode: 401,
      statusDescription: 'Unauthorized',
      headers: {
        'content-type': { value: 'text/html; charset=utf-8' },
        'cache-control': { value: 'no-store' },
      },
      body: '<h1>401 Unauthorized</h1><p>Authentication required.</p>',
    };
  }
  
  var token = authHeader.substring(7);
  
  // Parse JWT payload (base64 decode middle section)
  var parts = token.split('.');
  if (parts.length !== 3) {
    return {
      statusCode: 401,
      statusDescription: 'Unauthorized',
      headers: {
        'content-type': { value: 'text/html; charset=utf-8' },
        'cache-control': { value: 'no-store' },
      },
      body: '<h1>401 Unauthorized</h1><p>Invalid token format.</p>',
    };
  }
  
  // Decode payload
  var payload;
  try {
    var payloadBase64 = parts[1];
    // Add padding if needed
    while (payloadBase64.length % 4 !== 0) {
      payloadBase64 += '=';
    }
    var payloadJson = atob(payloadBase64);
    payload = JSON.parse(payloadJson);
  } catch (e) {
    return {
      statusCode: 401,
      statusDescription: 'Unauthorized',
      headers: {
        'content-type': { value: 'text/html; charset=utf-8' },
        'cache-control': { value: 'no-store' },
      },
      body: '<h1>401 Unauthorized</h1><p>Invalid token.</p>',
    };
  }
  
  // Get required roles from custom header
  var requiredRolesHeader = headers['x-required-roles'] ? headers['x-required-roles'].value : '';
  var requiredRoles = requiredRolesHeader ? requiredRolesHeader.split(',') : [];
  
  // Get user roles from JWT
  var userRoles = payload.roles || [];
  
  // Check if user has any required role
  var hasRole = false;
  for (var i = 0; i < requiredRoles.length; i++) {
    if (userRoles.indexOf(requiredRoles[i]) !== -1) {
      hasRole = true;
      break;
    }
  }
  
  if (!hasRole) {
    // Include CloudFront Request ID for incident tracking
    var requestId = event.context.requestId;
    return {
      statusCode: 302,
      statusDescription: 'Found',
      headers: {
        'location': { value: '/error.html?ref=' + requestId },
        'cache-control': { value: 'no-store' },
      },
    };
  }
  
  // Allow request to proceed
  return request;
}
