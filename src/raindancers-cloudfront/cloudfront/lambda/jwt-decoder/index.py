import json
import base64
from datetime import datetime

def handler(event, context):
    cookies = event.get('cookies', [])
    
    auth_token = None
    for cookie in cookies:
        if cookie.startswith('__Host-auth_session='):
            auth_token = cookie.split('=', 1)[1]
            break
    
    if not auth_token:
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
            },
            'body': '<html><body><h1>No JWT Found</h1><p>No auth_session cookie present.</p></body></html>'
        }
    
    try:
        parts = auth_token.split('.')
        if len(parts) != 3:
            raise ValueError('Invalid JWT format')
        
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        
        # Format timestamps
        nbf_time = datetime.fromtimestamp(payload.get('nbf', 0)).strftime('%Y-%m-%d %H:%M:%S') if 'nbf' in payload else 'N/A'
        exp_time = datetime.fromtimestamp(payload.get('exp', 0)).strftime('%Y-%m-%d %H:%M:%S') if 'exp' in payload else 'N/A'
        
        html = f'''
        <html>
        <head><title>JWT Decoder</title></head>
        <body style="font-family: monospace; padding: 20px;">
            <h1>JWT Token Details</h1>
            <p><strong>Not Before:</strong>	<span id="nbf">{nbf_time} UTC</span></p>
            <p><strong>Expires:</strong>		<span id="exp">{exp_time} UTC</span></p>
            <h2>Header</h2>
            <pre>{json.dumps(header, indent=2)}</pre>
            <h2>Payload</h2>
            <pre>{json.dumps(payload, indent=2)}</pre>
            <h2>Signature</h2>
            <pre>{parts[2]}</pre>
            <script>
                const nbf = {payload.get('nbf', 0)};
                const exp = {payload.get('exp', 0)};
                
                const offset = -new Date().getTimezoneOffset();
                const offsetHours = Math.floor(Math.abs(offset) / 60);
                const offsetMinutes = Math.abs(offset) % 60;
                const offsetSign = offset >= 0 ? '+' : '-';
                const offsetStr = `${{offsetSign}}${{String(offsetHours).padStart(2, '0')}}:${{String(offsetMinutes).padStart(2, '0')}}`;
                
                const options = {{ year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }};
                
                if (nbf) {{
                    document.getElementById('nbf').textContent = `${{new Date(nbf * 1000).toLocaleString('en-NZ', options)}} (UTC${{offsetStr}})`;
                }}
                if (exp) {{
                    document.getElementById('exp').textContent = `${{new Date(exp * 1000).toLocaleString('en-NZ', options)}} (UTC${{offsetStr}})`;
                }}
            </script>
        </body>
        </html>
        '''
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
            },
            'body': html
        }
    except Exception as e:
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
            },
            'body': f'<html><body><h1>Error Decoding JWT</h1><p>{str(e)}</p></body></html>'
        }
