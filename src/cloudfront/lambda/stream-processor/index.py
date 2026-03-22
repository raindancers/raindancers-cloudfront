import boto3
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

kvs_client = boto3.client('cloudfront-keyvaluestore')
KVS_ARN = os.environ['KVS_ARN']

def lambda_handler(event, context):
    """Triggered by DynamoDB Stream when TTL deletes expired sessions
    
    Automatically removes corresponding revocations from KVS.
    Only processes revoked sessions (not all TTL deletions).
    """
    
    deleted_count = 0
    
    for record in event['Records']:
        if record['eventName'] != 'REMOVE':
            continue
        
        if 'userIdentity' not in record or record['userIdentity'].get('type') != 'Service':
            continue
        
        old_image = record['dynamodb'].get('OldImage', {})
        
        pk = old_image.get('pk', {}).get('S', '')
        if not pk.startswith('SESSION#'):
            continue
        
        revoked = old_image.get('revoked', {}).get('BOOL', False)
        if not revoked:
            continue
        
        jti = old_image.get('jti', {}).get('S')
        if not jti:
            continue
        
        try:
            kvs_client.delete_key(
                KvsARN=KVS_ARN,
                Key=f'revoked:{jti}',
                IfMatch='*'
            )
            deleted_count += 1
            logger.info(f'Cleaned up expired revocation from KVS: {jti}')
        except Exception as e:
            logger.warning(f'Failed to delete revocation from KVS: {jti}, error: {e}')
    
    logger.info(f'Processed {len(event["Records"])} stream records, cleaned {deleted_count} revocations')
    return {'statusCode': 200, 'deletedCount': deleted_count}
