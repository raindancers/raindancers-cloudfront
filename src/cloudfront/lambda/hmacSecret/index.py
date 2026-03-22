import boto3
import json
import logging
import urllib3

logger = logging.getLogger()
logger.setLevel(logging.INFO)
http = urllib3.PoolManager()

def send_response(event, context, status, data=None):
    """Send response to CloudFormation"""
    response_body = {
        'Status': status,
        'Reason': f'See CloudWatch Log Stream: {context.log_stream_name}',
        'PhysicalResourceId': context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data or {}
    }
    
    json_response = json.dumps(response_body)
    headers = {'content-type': '', 'content-length': str(len(json_response))}
    
    try:
        http.request('PUT', event['ResponseURL'], body=json_response, headers=headers)
    except Exception as e:
        logger.error(f'Failed to send response: {e}')

def copy_secret_to_kvs(secret_arn, kvs_arn):
    """
    Core logic to copy HMAC secret from Secrets Manager to CloudFront KVS.
    Implements dual-secret rotation: stores both current and old secret for zero-downtime rotation.
    """
    logger.info(f'Copying secret from {secret_arn} to KVS {kvs_arn}')
    
    secrets_client = boto3.client('secretsmanager')
    secret_response = secrets_client.get_secret_value(SecretId=secret_arn)
    secret_data = json.loads(secret_response['SecretString'])
    new_secret = secret_data['hmac_key']
    
    logger.info('New secret retrieved from Secrets Manager')
    
    cf_client = boto3.client('cloudfront-keyvaluestore')
    
    kvs_response = cf_client.describe_key_value_store(KvsARN=kvs_arn)
    etag = kvs_response['ETag']
    logger.info(f'KVS ETag: {etag}')
    
    try:
        current_response = cf_client.get_key(
            KvsARN=kvs_arn,
            # amazonq-ignore-next-line
            Key='jwt.secret'
        )
        old_secret = current_response['Value']
        
        cf_client.put_key(
            KvsARN=kvs_arn,
            # amazonq-ignore-next-line
            Key='jwt.secret.old',
            Value=old_secret,
            IfMatch=etag
        )
        logger.info('Current secret preserved as old secret')
        
        kvs_response = cf_client.describe_key_value_store(KvsARN=kvs_arn)
        etag = kvs_response['ETag']
    except cf_client.exceptions.ResourceNotFoundException:
        logger.info('No existing secret found (first deployment)')
    except Exception as e:
        logger.warning(f'Could not preserve old secret: {e}')
    
    cf_client.put_key(
        KvsARN=kvs_arn,
        # amazonq-ignore-next-line
        Key='jwt.secret',
        Value=new_secret,
        IfMatch=etag
    )
    
    logger.info('New secret copied to CloudFront KVS successfully')
    logger.info('Dual-secret rotation complete: jwt.secret (new) + jwt.secret.old (previous)')

def handler(event, context):
    """
    Handler supporting both CloudFormation Custom Resource and direct Lambda invocations.
    """
    try:
        is_cfn_event = 'RequestType' in event and 'ResponseURL' in event
        
        if is_cfn_event:
            logger.info(f'CloudFormation Request Type: {event["RequestType"]}')
            request_type = event['RequestType']
            
            if request_type in ['Create', 'Update']:
                secret_arn = event['ResourceProperties']['SecretArn']
                kvs_arn = event['ResourceProperties']['KvsArn']
                
                copy_secret_to_kvs(secret_arn, kvs_arn)
                send_response(event, context, 'SUCCESS', {
                    'Message': 'Secret rotation complete with dual-secret support'
                })
                
            elif request_type == 'Delete':
                logger.info('Delete request - no cleanup needed')
                send_response(event, context, 'SUCCESS')
            
            else:
                logger.warning(f'Unknown request type: {request_type}')
                send_response(event, context, 'SUCCESS')
        else:
            logger.info('Direct invocation (non-CloudFormation)')
            secret_arn = event['ResourceProperties']['SecretArn']
            kvs_arn = event['ResourceProperties']['KvsArn']
            
            copy_secret_to_kvs(secret_arn, kvs_arn)
            
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'Secret copied successfully'})
            }
            
    except Exception as e:
        logger.error(f'Error: {str(e)}', exc_info=True)
        if 'ResponseURL' in event:
            send_response(event, context, 'FAILED')
        else:
            raise
