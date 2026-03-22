function decodeJWT(token) {
  try {
    var parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    var payloadBase64 = parts[1];
    while (payloadBase64.length % 4 !== 0) {
      payloadBase64 += '=';
    }
    var payloadJson = atob(payloadBase64);
    return JSON.parse(payloadJson);
  } catch (e) {
    return null;
  }
}

function getJWTFromHeaders(headers) {
  var authHeader = headers['authorization'] ? headers['authorization'].value : '';
  if (!authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7);
}

function createRedirect(location, requestId) {
  return {
    statusCode: 302,
    statusDescription: 'Found',
    headers: {
      'location': { value: location + '?ref=' + requestId },
      'cache-control': { value: 'no-store' },
    },
  };
}

function createErrorResponse(statusCode, message) {
  return {
    statusCode: statusCode,
    statusDescription: message,
    headers: {
      'content-type': { value: 'text/html; charset=utf-8' },
      'cache-control': { value: 'no-store' },
    },
    body: '<h1>' + statusCode + ' ' + message + '</h1>',
  };
}
