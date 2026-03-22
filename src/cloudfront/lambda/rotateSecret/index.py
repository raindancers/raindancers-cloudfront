import json
import boto3
import secrets
import string
import os
import time

secretsmanager = boto3.client('secretsmanager')
lambda_client = boto3.client('lambda')

SECRET_ARN = os.environ['SECRET_ARN']
COPY_LAMBDA_ARN = os.environ['COPY_LAMBDA_ARN']
KVS_ARN = os.environ['KVS_ARN']

MAX_RETRIES = 3
RETRY_DELAY = 2

def generate_hmac_key(length=64):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def invoke_copy_lambda_with_retry(payload):
    """Invoke copy lambda synchronously with retry logic"""
    for attempt in range(MAX_RETRIES):
        try:
            print(f'Invoking copy lambda (attempt {attempt + 1}/{MAX_RETRIES})')
            response = lambda_client.invoke(
                FunctionName=COPY_LAMBDA_ARN,
                InvocationType='RequestResponse',
                Payload=json.dumps(payload)
            )
            
            response_payload = json.loads(response['Payload'].read())
            
            if response['StatusCode'] == 200:
                if 'statusCode' in response_payload and response_payload['statusCode'] == 200:
                    print('Copy lambda invoked successfully')
                    return response_payload
                elif 'FunctionError' in response:
                    raise Exception(f"Copy lambda error: {response_payload}")
                else:
                    print('Copy lambda completed successfully')
                    return response_payload
            else:
                raise Exception(f"Lambda invocation failed with status {response['StatusCode']}")
                
        except Exception as e:
            print(f'Attempt {attempt + 1} failed: {str(e)}')
            if attempt < MAX_RETRIES - 1:
                print(f'Retrying in {RETRY_DELAY} seconds...')
                time.sleep(RETRY_DELAY)
            else:
                raise Exception(f'Failed to invoke copy lambda after {MAX_RETRIES} attempts: {str(e)}')

def handler(event, context):
    print(f"Rotating secret: {SECRET_ARN}")
    
    response = secretsmanager.get_secret_value(SecretId=SECRET_ARN)
    current_secret = json.loads(response['SecretString'])
    
    new_hmac_key = generate_hmac_key()
    
    current_secret['hmac_key'] = new_hmac_key
    
    secretsmanager.put_secret_value(
        SecretId=SECRET_ARN,
        SecretString=json.dumps(current_secret)
    )
    
    print(f"Secret rotated in Secrets Manager")
    
    payload = {
        'ResourceProperties': {
            'SecretArn': SECRET_ARN,
            'KvsArn': KVS_ARN
        }
    }
    
    invoke_copy_lambda_with_retry(payload)
    
    print(f"KVS updated successfully")
    
    return {
        'statusCode': 200,
        'body': json.dumps('Secret rotated and synchronized successfully')
    }
