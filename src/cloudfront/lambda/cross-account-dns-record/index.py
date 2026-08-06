import boto3
import json
import urllib3

http = urllib3.PoolManager()


def send_response(event, context, status, reason, physical_id, data=None):
    body = json.dumps({
        'Status': status,
        'Reason': reason,
        'PhysicalResourceId': physical_id,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data or {},
    })
    try:
        http.request('PUT', event['ResponseURL'], body=body.encode('utf-8'), headers={'Content-Type': ''})
    except Exception as e:
        print(f'Failed to send response to CloudFormation: {str(e)}')


def assume_role(role_arn):
    sts = boto3.client('sts')
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName='CrossAccountDnsRecord',
        DurationSeconds=900,
    )
    credentials = response['Credentials']
    return boto3.client(
        'route53',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )


def build_change_batch(action, props):
    record_name = props['RecordName']
    record_type = props['RecordType']

    if 'AliasTarget' in props:
        alias = props['AliasTarget']
        resource_record_set = {
            'Name': record_name,
            'Type': record_type,
            'AliasTarget': {
                'DNSName': alias['DNSName'],
                'HostedZoneId': alias['HostedZoneId'],
                'EvaluateTargetHealth': alias.get('EvaluateTargetHealth', 'false').lower() == 'true',
            },
        }
    else:
        resource_records = props.get('ResourceRecords', [])
        ttl = int(props.get('TTL', '300'))
        resource_record_set = {
            'Name': record_name,
            'Type': record_type,
            'TTL': ttl,
            'ResourceRecords': [{'Value': r} for r in resource_records],
        }

    return {
        'Changes': [{
            'Action': action,
            'ResourceRecordSet': resource_record_set,
        }],
    }


def handler(event, context):
    physical_id = event.get('PhysicalResourceId', context.log_stream_name)

    try:
        props = event['ResourceProperties']
        hosted_zone_id = props['HostedZoneId']
        role_arn = props['RoleArn']
        record_name = props['RecordName']
        record_type = props['RecordType']

        route53 = assume_role(role_arn)

        if event['RequestType'] == 'Create':
            change_batch = build_change_batch('UPSERT', props)
            route53.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch=change_batch,
            )
            physical_id = f'{hosted_zone_id}/{record_name}/{record_type}'

        elif event['RequestType'] == 'Update':
            old_props = event.get('OldResourceProperties', {})
            old_name = old_props.get('RecordName', '')
            old_type = old_props.get('RecordType', '')

            # If record name or type changed, delete the old record first
            if old_name != record_name or old_type != record_type:
                try:
                    old_change_batch = build_change_batch('DELETE', old_props)
                    route53.change_resource_record_sets(
                        HostedZoneId=old_props.get('HostedZoneId', hosted_zone_id),
                        ChangeBatch=old_change_batch,
                    )
                except Exception as e:
                    print(f'Warning: failed to delete old record: {str(e)}')

            # UPSERT the new record
            change_batch = build_change_batch('UPSERT', props)
            route53.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch=change_batch,
            )
            physical_id = f'{hosted_zone_id}/{record_name}/{record_type}'

        elif event['RequestType'] == 'Delete':
            try:
                change_batch = build_change_batch('DELETE', props)
                route53.change_resource_record_sets(
                    HostedZoneId=hosted_zone_id,
                    ChangeBatch=change_batch,
                )
            except Exception as e:
                # If record doesn't exist, that's fine on delete
                print(f'Warning: failed to delete record (may not exist): {str(e)}')

        send_response(event, context, 'SUCCESS', 'OK', physical_id)

    except Exception as e:
        print(f'Error: {str(e)}')
        send_response(event, context, 'FAILED', str(e), physical_id)
