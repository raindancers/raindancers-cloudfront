import cf from 'cloudfront';
var crypto = require('crypto');

const kvsHandle = cf.kvs();
const COGNITO_DOMAIN = 'COGNITO_DOMAIN_PLACEHOLDER';
const COGNITO_CLIENT_ID = 'CLIENT_ID_PLACEHOLDER';
const REDIRECT_URI = 'REDIRECT_URI_PLACEHOLDER';

function base64urlDecode(str) {
  var base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return atob(base64);
}

function constantTimeCompare(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

async function validateHmacSignature(token) {
  var parts = token.split('.');
  if (parts.length !== 3) {
    return false;
  }

  var signingInput = parts[0] + '.' + parts[1];
  var providedSignature = parts[2];

  try {
    var secret = await kvsHandle.get('jwt.secret');
    if (!secret) {
      return false;
    }

    var hmac = crypto.createHmac('sha256', secret);
    hmac.update(signingInput);
    var computedSignature = hmac.digest('base64url');

    if (constantTimeCompare(computedSignature, providedSignature)) {
      return true;
    }

    try {
      var oldSecret = await kvsHandle.get('jwt.secret.old');
      if (oldSecret) {
        var oldHmac = crypto.createHmac('sha256', oldSecret);
        oldHmac.update(signingInput);
        var oldComputedSignature = oldHmac.digest('base64url');
        if (constantTimeCompare(oldComputedSignature, providedSignature)) {
          return true;
        }
      }
    } catch (e) {}
    return false;
  } catch (e) {
    return false;
  }
}

function generateCodeVerifier() {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  var result = '';
  for (var i = 0; i < 43; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateCodeChallenge(verifier) {
  var hash = crypto.createHash('sha256');
  hash.update(verifier);
  return hash.digest('base64url');
}

function generateState(originalPath) {
  var randomPart = Math.random().toString(36).substring(2) + Date.now().toString(36);
  var stateObj = { r: randomPart, p: originalPath };
  return btoa(JSON.stringify(stateObj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function buildCognitoAuthUrl(state, codeChallenge) {
  var params = [
    'client_id=' + encodeURIComponent(COGNITO_CLIENT_ID),
    'redirect_uri=' + encodeURIComponent(REDIRECT_URI),
    'response_type=code',
    'scope=' + encodeURIComponent('openid profile email'),
    'state=' + encodeURIComponent(state),
    'code_challenge=' + encodeURIComponent(codeChallenge),
    'code_challenge_method=S256'
  ];
  return 'https://' + COGNITO_DOMAIN + '/oauth2/authorize?' + params.join('&');
}

function getOriginalPath(request) {
  var qs = request.querystring;
  if (!qs) {
    return request.uri;
  }
  if (typeof qs === 'object') {
    var params = [];
    for (var key in qs) {
      if (qs.hasOwnProperty(key)) {
        var val = qs[key];
        if (val && val.value !== undefined) {
          params.push(encodeURIComponent(key) + '=' + encodeURIComponent(val.value));
        } else {
          params.push(encodeURIComponent(key) + '=' + encodeURIComponent(val));
        }
      }
    }
    return request.uri + (params.length > 0 ? '?' + params.join('&') : '');
  }
  return request.uri + '?' + qs;
}

function redirectToAuth(originalPath) {
  var state = generateState(originalPath);
  var codeVerifier = generateCodeVerifier();
  var codeChallenge = generateCodeChallenge(codeVerifier);
  return {
    statusCode: 302,
    headers: {
      location: { value: buildCognitoAuthUrl(state, codeChallenge) },
      'cache-control': { value: 'no-store' }
    },
    cookies: {
      oauth_state: {
        value: state,
        attributes: 'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600'
      },
      code_verifier: {
        value: codeVerifier,
        attributes: 'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600'
      }
    }
  };
}

async function checkAuth(event, decodedPayload, requiredRoles, roleMatchMode) {
  var request = event.request;
  if (request.uri === '/oauth2/callback') {
    return { pass: true, payload: null };
  }
  if (decodedPayload) {
    return { pass: true, payload: decodedPayload };
  }
  var cookies = request.cookies;
  var originalPath = getOriginalPath(request);
  if (!cookies['__Host-auth_session']) {
    return { pass: false, response: redirectToAuth(originalPath) };
  }
  var token = cookies['__Host-auth_session'].value;
  if (!token || token.length === 0) {
    return { pass: false, response: redirectToAuth(originalPath) };
  }
  try {
    var parts = token.split('.');
    if (parts.length !== 3) {
      return { pass: false, response: redirectToAuth(originalPath) };
    }
    var isValid = await validateHmacSignature(token);
    if (!isValid) {
      return { pass: false, response: redirectToAuth(originalPath) };
    }
    var payload = JSON.parse(base64urlDecode(parts[1]));
    var now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return { pass: false, response: redirectToAuth(originalPath) };
    }
    var jti = payload.jti;
    if (jti) {
      try {
        var isRevoked = await kvsHandle.get('revoked:' + jti);
        if (isRevoked) {
          return { pass: false, response: redirectToAuth(originalPath) };
        }
      } catch (e) {}
    }

    if (requiredRoles && requiredRoles.length > 0) {
      var userRoles = payload.roles || [];
      var hasAccess = false;
      if (roleMatchMode === 'AND') {
        hasAccess = true;
        for (var i = 0; i < requiredRoles.length; i++) {
          if (userRoles.indexOf(requiredRoles[i]) === -1) {
            hasAccess = false;
            break;
          }
        }
      } else {
        for (var i = 0; i < requiredRoles.length; i++) {
          if (userRoles.indexOf(requiredRoles[i]) !== -1) {
            hasAccess = true;
            break;
          }
        }
      }
      if (!hasAccess) {
        return {
          pass: false,
          response: {
            statusCode: 403,
            statusDescription: 'Forbidden',
            body: 'Access denied: insufficient roles'
          }
        };
      }
    }

    return { pass: true, payload: payload };
  } catch (e) {
    return { pass: false, response: redirectToAuth(originalPath) };
  }
}
