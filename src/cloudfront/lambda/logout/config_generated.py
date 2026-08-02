# Generated configuration — placeholder replaced at CDK synth time.
# This file is overwritten during bundling with the actual secret name and region.
import json
import boto3
import logging

logger = logging.getLogger()

CONFIG_SECRET_NAME = 'PLACEHOLDER_SECRET_NAME'
CONFIG_REGION = 'PLACEHOLDER_REGION'


def get_config():
    """Load configuration from AWS Secrets Manager.

    Returns:
        Dict containing all auth configuration including HMAC secret,
        Entra tenant/client IDs, DynamoDB table details, and KVS ARN.
    """
    logger.info(f'Loading config from Secrets Manager: {CONFIG_SECRET_NAME} in {CONFIG_REGION}')
    try:
        client = boto3.client('secretsmanager', region_name=CONFIG_REGION)
        response = client.get_secret_value(SecretId=CONFIG_SECRET_NAME)
        return json.loads(response['SecretString'])
    except Exception as e:
        logger.error(f'Failed to get secret: {e}')
        raise
