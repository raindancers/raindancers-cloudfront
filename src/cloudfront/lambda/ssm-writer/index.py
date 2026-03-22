import boto3
import json
import urllib3

http = urllib3.PoolManager()

def send_response(event, context, status, reason, physical_id):
    body = json.dumps({
        'Status': status,
        'Reason': reason,
        'PhysicalResourceId': physical_id,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': {},
    })
    try:
        http.request('PUT', event['ResponseURL'], body=body.encode('utf-8'), headers={'Content-Type': ''})
    except Exception as e:
        print(f'Failed to send response to CloudFormation: {str(e)}')

def handler(event, context):
    physical_id = event.get('PhysicalResourceId', context.log_stream_name)
    try:
        props = event['ResourceProperties']
        prefix = props['Prefix']
        params = json.loads(props['Params'])
        region = props.get('Region', 'us-east-1')
        ssm = boto3.client('ssm', region_name=region)

        if event['RequestType'] in ('Create', 'Update'):
            for key, value in params.items():
                ssm.put_parameter(Name=f'{prefix}/{key}', Value=value, Type='String', Overwrite=True)
            physical_id = prefix

        elif event['RequestType'] == 'Delete':
            names = [f'{prefix}/{key}' for key in params]
            for i in range(0, len(names), 10):
                ssm.delete_parameters(Names=names[i:i+10])

        send_response(event, context, 'SUCCESS', 'OK', physical_id)
    except Exception as e:
        print(f'Error: {str(e)}')
        send_response(event, context, 'FAILED', str(e), physical_id)
