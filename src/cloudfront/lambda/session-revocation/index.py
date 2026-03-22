import json
import boto3
import logging
import os
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.client('dynamodb')
kvs_client = boto3.client('cloudfront-keyvaluestore')

TABLE_NAME = os.environ['TABLE_NAME']
KVS_ARN = os.environ['KVS_ARN']

def lambda_handler(event, context):
    """Triggered by SNS message to revoke user sessions
    
    Message format: {"action": "revoke", "userId": "user@example.com"}
    """
    
    for record in event['Records']:
        try:
            message = json.loads(record['Sns']['Message'])
            
            if message.get('action') != 'revoke':
                logger.warning(f'Unknown action: {message.get("action")}')
                continue
            
            user_id = message.get('userId')
            if not user_id:
                logger.error('Missing userId in revocation message')
                continue
            
            logger.info(f'Processing revocation for user: {user_id}')
            
            response = dynamodb.query(
                TableName=TABLE_NAME,
                IndexName='GSI1',
                KeyConditionExpression='gsi1pk = :pk',
                FilterExpression='revoked = :false',
                ExpressionAttributeValues={
                    ':pk': {'S': f'USER#{user_id}'},
                    ':false': {'BOOL': False}
                }
            )
            
            revoked_count = 0
            for item in response.get('Items', []):
                jti = item['jti']['S']
                
                dynamodb.update_item(
                    TableName=TABLE_NAME,
                    Key={
                        'pk': {'S': f'SESSION#{user_id}'},
                        'sk': {'S': f'SESSION#{jti}'}
                    },
                    UpdateExpression='SET revoked = :true, revokedAt = :now',
                    ExpressionAttributeValues={
                        ':true': {'BOOL': True},
                        ':now': {'N': str(int(time.time()))}
                    }
                )
                
                kvs_client.put_key(
                    KvsARN=KVS_ARN,
                    Key=f'revoked:{jti}',
                    Value=str(int(time.time())),
                    IfMatch='*'
                )
                
                revoked_count += 1
            
            logger.info(f'Revoked {revoked_count} sessions for user: {user_id}')
            
        except Exception as e:
            logger.error(f'Error processing revocation: {str(e)}')
            raise
    
    return {'statusCode': 200, 'body': 'Revocation processed'}
