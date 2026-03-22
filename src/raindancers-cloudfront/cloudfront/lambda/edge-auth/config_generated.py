# Generated configuration
import json
import boto3
import os

# Well-known secret name pattern
CONFIG_SECRET_NAME = 'cloudfront-auth-config-cdk-api-dev'

def get_config():
    client = boto3.client('secretsmanager', region_name='us-east-1')
    response = client.get_secret_value(SecretId=CONFIG_SECRET_NAME)
    return json.loads(response['SecretString'])
