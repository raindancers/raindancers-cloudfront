import cf from 'cloudfront';
var crypto = require('crypto');

const kvsHandle = cf.kvs();

const AZURE_TENANT_ID = 'TENANT_ID_PLACEHOLDER';
const AZURE_CLIENT_ID = 'CLIENT_ID_PLACEHOLDER';
const REDIRECT_URI = 'REDIRECT_URI_PLACEHOLDER';
const COOKIE_DOMAIN = 'COOKIE_DOMAIN_PLACEHOLDER';

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
        // Get current secret
        var secret = await kvsHandle.get('jwt.secret');
        if (!secret) {
            return false;
        }
        
        // Try current secret first
        var hmac = crypto.createHmac('sha256', secret);
        hmac.update(signingInput);
        var computedSignature = hmac.digest('base64url');
        
        if (constantTimeCompare(computedSignature, providedSignature)) {
            return true;  // Valid with current secret
        }
        
        // Try old secret (for tokens signed before rotation)
        try {
            var oldSecret = await kvsHandle.get('jwt.secret.old');
            if (oldSecret) {
                var oldHmac = crypto.createHmac('sha256', oldSecret);
                oldHmac.update(signingInput);
                var oldComputedSignature = oldHmac.digest('base64url');
                
                if (constantTimeCompare(oldComputedSignature, providedSignature)) {
                    console.log('Token validated with old secret (pre-rotation)');
                    return true;  // Valid with old secret
                }
            }
        } catch (e) {
            // Old secret doesn't exist (first deployment or old secret expired)
        }
        
        return false;  // Invalid signature with both secrets
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

function buildAzureAuthUrl(state, codeChallenge) {
    var params = [
        'client_id=' + encodeURIComponent(AZURE_CLIENT_ID),
        'redirect_uri=' + encodeURIComponent(REDIRECT_URI),
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
            location: { value: buildAzureAuthUrl(state, codeChallenge) },
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

async function handler(event) {
    var request = event.request;
    
    // Skip auth check for OAuth callback path
    if (request.uri === '/oauth2/callback') {
        return request;
    }
    
    var cookies = request.cookies;
    var host = request.headers.host ? request.headers.host.value : '';
    
    // Check for session cookie (supports both __Secure- with domain and __Host- without)
    var sessionCookie = cookies['__Secure-auth_session'] || cookies['__Host-auth_session'];
    if (!sessionCookie) {
        return redirectToAuth(getOriginalPath(request), host);
    }
    
    var token = sessionCookie.value;
    
    if (!token || token.length === 0) {
        return redirectToAuth(getOriginalPath(request), host);
    }
    
    try {
        var originalPath = getOriginalPath(request);
        var parts = token.split('.');
        
        if (parts.length !== 3) {
            return redirectToAuth(originalPath, host);
        }
        
        var isValid = await validateHmacSignature(token);
        if (!isValid) {
            return redirectToAuth(originalPath, host);
        }
        
        var payload = JSON.parse(base64urlDecode(parts[1]));
        var now = Math.floor(Date.now() / 1000);
        
        if (payload.exp && payload.exp < now) {
            return redirectToAuth(originalPath, host);
        }
        
        // Check if session is revoked (denylist approach)
        var jti = payload.jti;
        if (jti) {
            try {
                var isRevoked = await kvsHandle.get('revoked:' + jti);
                if (isRevoked) {
                    console.log('Session revoked: ' + jti);
                    return redirectToAuth(originalPath, host);
                }
            } catch (e) {
                console.log('KVS error checking revocation: ' + e);
            }
        }
        
        return request;
    } catch (e) {
        return redirectToAuth(getOriginalPath(request), host);
    }
}
