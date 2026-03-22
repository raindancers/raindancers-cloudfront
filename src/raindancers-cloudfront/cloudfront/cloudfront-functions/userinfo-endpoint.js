// CloudFront Function: User Info Endpoint (viewer-request)
// Purpose: Validate JWT and return user info JSON without exposing full JWT
// Security: Validates JWT signature, returns only name and roles, calculates cache expiration

import cf from 'cloudfront';
var crypto = require('crypto');

const kvsHandle = cf.kvs();

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
                
                if (constantTimeCompare(oldComputedSignature, oldComputedSignature)) {
                    return true;
                }
            }
        } catch (e) {
            // Old secret doesn't exist
        }
        
        return false;
    } catch (e) {
        return false;
    }
}

function extractUserInfo(token, nameFields) {
    try {
        var parts = token.split('.');
        if (parts.length !== 3) {
            return null;
        }
        
        var payload = JSON.parse(base64urlDecode(parts[1]));
        
        // Extract name using ordered fallback list
        var username = 'User';
        for (var i = 0; i < nameFields.length; i++) {
            if (payload[nameFields[i]]) {
                username = payload[nameFields[i]];
                break;
            }
        }
        
        // Extract roles (default to empty array)
        var roles = payload.roles || [];
        
        // Extract expiration for cache control
        var exp = payload.exp || 0;
        
        return {
            name: username,
            roles: roles,
            exp: exp
        };
    } catch (e) {
        console.log('Failed to extract user info from JWT: ' + e);
        return null;
    }
}

async function handler(event) {
    var request = event.request;
    
    // Extract JWT from request cookies
    var cookies = request.cookies;
    if (!cookies['__Host-auth_session']) {
        return {
            statusCode: 401,
            statusDescription: 'Unauthorized',
            headers: {
                'content-type': { value: 'application/json' },
                'cache-control': { value: 'no-store' }
            },
            body: {
                encoding: 'text',
                data: JSON.stringify({ error: 'No session found' })
            }
        };
    }
    
    var token = cookies['__Host-auth_session'].value;
    if (!token) {
        return {
            statusCode: 401,
            statusDescription: 'Unauthorized',
            headers: {
                'content-type': { value: 'application/json' },
                'cache-control': { value: 'no-store' }
            },
            body: {
                encoding: 'text',
                data: JSON.stringify({ error: 'Invalid session' })
            }
        };
    }
    
    // Validate JWT signature
    var isValid = await validateHmacSignature(token);
    if (!isValid) {
        return {
            statusCode: 401,
            statusDescription: 'Unauthorized',
            headers: {
                'content-type': { value: 'application/json' },
                'cache-control': { value: 'no-store' }
            },
            body: {
                encoding: 'text',
                data: JSON.stringify({ error: 'Invalid JWT signature' })
            }
        };
    }
    
    // NOTE: This array is automatically replaced by CDK with configured JWT claim fields
    var nameFields = ['key1', 'key2', 'key3'];
    
    // Extract user info from JWT
    var userInfo = extractUserInfo(token, nameFields);
    if (!userInfo) {
        return {
            statusCode: 500,
            statusDescription: 'Internal Server Error',
            headers: {
                'content-type': { value: 'application/json' },
                'cache-control': { value: 'no-store' }
            },
            body: {
                encoding: 'text',
                data: JSON.stringify({ error: 'Failed to parse JWT' })
            }
        };
    }
    
    // Calculate cache duration from JWT expiration
    var now = Math.floor(Date.now() / 1000);
    var maxAge = userInfo.exp - now;
    
    // Ensure maxAge is positive and reasonable
    if (maxAge <= 0) {
        maxAge = 0;
    } else if (maxAge > 3600) {
        maxAge = 3600; // Cap at 1 hour for safety
    }
    
    // Return user info as JSON with dynamic cache control
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {
            'content-type': { value: 'application/json' },
            'cache-control': { value: 'private, max-age=' + maxAge }
        },
        body: {
            encoding: 'text',
            data: JSON.stringify({
                name: userInfo.name,
                roles: userInfo.roles
            })
        }
    };
}
