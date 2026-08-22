import cf from 'cloudfront';
var crypto = require('crypto');

const kvsHandle = cf.kvs();
const AZURE_TENANT_ID = 'TENANT_ID_PLACEHOLDER';
const AZURE_CLIENT_ID = 'CLIENT_ID_PLACEHOLDER';
const REDIRECT_URI = 'REDIRECT_URI_PLACEHOLDER';
const COOKIE_DOMAIN = 'COOKIE_DOMAIN_PLACEHOLDER';
const ENABLE_HEADER_INJECTION = ENABLE_HEADER_INJECTION_PLACEHOLDER;
const HEADER_INJECTION_MAP = HEADER_INJECTION_MAP_PLACEHOLDER;
const HEADER_INJECTION_KEYS = HEADER_INJECTION_KEYS_PLACEHOLDER;
const ENABLE_REFRESH = ENABLE_REFRESH_PLACEHOLDER;

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

function generateState(originalPath, host) {
  var randomPart = Math.random().toString(36).substring(2) + Date.now().toString(36);
  var stateObj = {
    r: randomPart,
    p: originalPath,
    h: host
  };
  return btoa(JSON.stringify(stateObj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function buildAzureAuthUrl(state, codeChallenge, host) {
  // Use the actual request host for redirect_uri so login returns to the
  // originating subdomain. Falls back to the baked REDIRECT_URI if host is absent.
  var redirectUri = host ? 'https://' + host + '/oauth2/callback' : REDIRECT_URI;
  var params = [
    'client_id=' + encodeURIComponent(AZURE_CLIENT_ID),
    'redirect_uri=' + encodeURIComponent(redirectUri),
    'response_type=code',
    'scope=' + encodeURIComponent('openid profile email'),
    'state=' + encodeURIComponent(state),
    'code_challenge=' + encodeURIComponent(codeChallenge),
    'code_challenge_method=S256'
  ];
  
  return 'https://login.microsoftonline.com/' + AZURE_TENANT_ID + 
         '/oauth2/v2.0/authorize?' + params.join('&');
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

function redirectToAuth(originalPath, host) {
  var state = generateState(originalPath, host);
  var codeVerifier = generateCodeVerifier();
  var codeChallenge = generateCodeChallenge(codeVerifier);
  var domainAttr = COOKIE_DOMAIN ? '; Domain=' + COOKIE_DOMAIN : '';
  return {
    statusCode: 302,
    headers: {
      location: { value: buildAzureAuthUrl(state, codeChallenge, host) },
      'cache-control': { value: 'no-store' }
    },
    cookies: {
      oauth_state: {
        value: state,
        attributes: 'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600' + domainAttr
      },
      code_verifier: {
        value: codeVerifier,
        attributes: 'HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600' + domainAttr
      }
    }
  };
}

// Redirect to the refresh endpoint for silent token renewal.
function redirectToRefresh(originalPath, host) {
  var returnTo = host ? 'https://' + host + originalPath : originalPath;
  return {
    statusCode: 302,
    headers: {
      location: { value: '/oauth2/refresh?return_to=' + encodeURIComponent(returnTo) },
      'cache-control': { value: 'no-store' }
    }
  };
}

async function checkAuth(event, decodedPayload, requiredRoles, roleMatchMode) {
  var request = event.request;

  // Strip externally-provided identity headers from ALL requests (prevents spoofing).
  // These headers are ONLY set by this function from validated JWT claims.
  if (ENABLE_HEADER_INJECTION) {
    var headersToStrip = HEADER_INJECTION_KEYS;
    for (var h = 0; h < headersToStrip.length; h++) {
      delete request.headers[headersToStrip[h]];
    }
  }

  if (request.uri.indexOf('/oauth2/') === 0) {
    return { pass: true, payload: null };
  }
  if (decodedPayload) {
    return { pass: true, payload: decodedPayload };
  }
  var cookies = request.cookies;
  var originalPath = getOriginalPath(request);
  var host = request.headers.host ? request.headers.host.value : '';
  var sessionCookie = cookies['__Secure-auth_session'] || cookies['__Host-auth_session'];
  if (!sessionCookie) {
    return {
      pass: false,
      response: redirectToAuth(originalPath, host)
    };
  }
  var token = sessionCookie.value;
  if (!token || token.length === 0) {
    return {
      pass: false,
      response: redirectToAuth(originalPath, host)
    };
  }
  try {
    var parts = token.split('.');
    if (parts.length !== 3) {
      return {
        pass: false,
        response: redirectToAuth(originalPath, host)
      };
    }
    var isValid = await validateHmacSignature(token);
    if (!isValid) {
      return {
        pass: false,
        response: redirectToAuth(originalPath, host)
      };
    }
    var payload = JSON.parse(base64urlDecode(parts[1]));
    var now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      if (ENABLE_REFRESH) {
        // Token is expired but signature was valid — redirect to refresh endpoint
        return {
          pass: false,
          response: redirectToRefresh(originalPath, host)
        };
      }
      return {
        pass: false,
        response: redirectToAuth(originalPath, host)
      };
    }
    var jti = payload.jti;
    if (jti) {
      try {
        var isRevoked = await kvsHandle.get('revoked:' + jti);
        if (isRevoked) {
          return {
            pass: false,
            response: redirectToAuth(originalPath, host)
          };
        }
      } catch (e) {}
    }
    
    // Role check (if required roles provided)
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
    return {
      pass: false,
      response: redirectToAuth(originalPath, host)
    };
  }
}

function injectAzureToken(request, cookies) {
  var azureToken = cookies['__Host-azure_token'] || cookies['__Secure-azure_token'];
  if (azureToken && azureToken.value) {
    request.headers['x-azure-token'] = {
      value: azureToken.value
    };
  }
  return request;
}

// Inject identity claims from validated JWT payload into request headers.
function injectClaimsHeaders(request, payload) {
  if (!ENABLE_HEADER_INJECTION || !payload) return request;
  var mapping = HEADER_INJECTION_MAP;
  for (var headerName in mapping) {
    if (mapping.hasOwnProperty(headerName)) {
      var val = payload[mapping[headerName]];
      if (val !== undefined && val !== null) {
        request.headers[headerName] = { value: String(val) };
      }
    }
  }
  return request;
}
