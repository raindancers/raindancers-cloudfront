import boto3
import json
import time
import urllib3

http = urllib3.PoolManager()

POLL_INTERVAL = 10
DEFAULT_TIMEOUT = 300


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
        RoleSessionName='CrossAccountDnsCertificate',
        DurationSeconds=900,
    )
    credentials = response['Credentials']
    return boto3.client(
        'route53',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )


def get_validation_records(acm, certificate_arn):
    """Poll until DomainValidationOptions contains ResourceRecord entries."""
    for _ in range(30):
        response = acm.describe_certificate(CertificateArn=certificate_arn)
        options = response['Certificate'].get('DomainValidationOptions', [])
        if options and all('ResourceRecord' in opt for opt in options):
            return options
        time.sleep(2)
    raise TimeoutError('Timed out waiting for ACM to provide validation records')


def upsert_validation_records(route53, hosted_zone_id, validation_options):
    """Create CNAME validation records in the cross-account hosted zone."""
    changes = []
    seen = set()
    for opt in validation_options:
        record = opt['ResourceRecord']
        key = (record['Name'], record['Value'])
        if key in seen:
            continue
        seen.add(key)
        changes.append({
            'Action': 'UPSERT',
            'ResourceRecordSet': {
                'Name': record['Name'],
                'Type': record['Type'],
                'TTL': 300,
                'ResourceRecords': [{'Value': record['Value']}],
            },
        })

    if changes:
        route53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={'Changes': changes},
        )

    return changes


def delete_validation_records(route53, hosted_zone_id, validation_options):
    """Delete CNAME validation records from the cross-account hosted zone."""
    changes = []
    seen = set()
    for opt in validation_options:
        record = opt.get('ResourceRecord')
        if not record:
            continue
        key = (record['Name'], record['Value'])
        if key in seen:
            continue
        seen.add(key)
        changes.append({
            'Action': 'DELETE',
            'ResourceRecordSet': {
                'Name': record['Name'],
                'Type': record['Type'],
                'TTL': 300,
                'ResourceRecords': [{'Value': record['Value']}],
            },
        })

    if changes:
        try:
            route53.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={'Changes': changes},
            )
        except Exception as e:
            print(f'Warning: failed to delete validation records: {str(e)}')


def wait_for_issued(acm, certificate_arn, timeout):
    """Poll ACM until certificate is ISSUED or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = acm.describe_certificate(CertificateArn=certificate_arn)
        status = response['Certificate']['Status']
        if status == 'ISSUED':
            return True
        if status == 'FAILED':
            reason = response['Certificate'].get('FailureReason', 'Unknown')
            raise Exception(f'Certificate validation failed: {reason}')
        time.sleep(POLL_INTERVAL)
    raise TimeoutError(f'Certificate not issued within {timeout}s')


def handler(event, context):
    physical_id = event.get('PhysicalResourceId', 'none')

    try:
        props = event['ResourceProperties']
        domain_name = props['DomainName']
        hosted_zone_id = props['HostedZoneId']
        validation_role_arn = props['ValidationRoleArn']
        subject_alternative_names = props.get('SubjectAlternativeNames', [])
        validation_timeout = int(props.get('ValidationTimeout', str(DEFAULT_TIMEOUT)))
        cleanup_validation_records_flag = props.get('CleanupValidationRecords', 'true').lower() == 'true'
        certificate_region = props.get('CertificateRegion', None)

        acm = boto3.client('acm', region_name=certificate_region) if certificate_region else boto3.client('acm')

        if event['RequestType'] == 'Create':
            # Request the certificate
            request_params = {
                'DomainName': domain_name,
                'ValidationMethod': 'DNS',
            }
            if subject_alternative_names:
                request_params['SubjectAlternativeNames'] = subject_alternative_names

            response = acm.request_certificate(**request_params)
            certificate_arn = response['CertificateArn']
            physical_id = certificate_arn

            # Get validation records from ACM
            validation_options = get_validation_records(acm, certificate_arn)

            # Assume role and create validation CNAMEs in cross-account zone
            route53 = assume_role(validation_role_arn)
            upsert_validation_records(route53, hosted_zone_id, validation_options)

            # Wait for certificate to be issued
            try:
                wait_for_issued(acm, certificate_arn, validation_timeout)
            except Exception as e:
                # Cleanup on failure
                print(f'Validation failed, cleaning up: {str(e)}')
                delete_validation_records(route53, hosted_zone_id, validation_options)
                try:
                    acm.delete_certificate(CertificateArn=certificate_arn)
                except Exception as cleanup_err:
                    print(f'Warning: failed to delete certificate: {str(cleanup_err)}')
                raise

            # Optionally clean up validation records after issuance
            if cleanup_validation_records_flag:
                delete_validation_records(route53, hosted_zone_id, validation_options)

            send_response(event, context, 'SUCCESS', 'OK', physical_id, {
                'CertificateArn': certificate_arn,
            })

        elif event['RequestType'] == 'Update':
            old_props = event.get('OldResourceProperties', {})
            old_domain = old_props.get('DomainName', '')
            old_sans = old_props.get('SubjectAlternativeNames', [])

            # If domain or SANs changed, must replace the certificate
            if old_domain != domain_name or sorted(old_sans) != sorted(subject_alternative_names):
                # Create new certificate
                request_params = {
                    'DomainName': domain_name,
                    'ValidationMethod': 'DNS',
                }
                if subject_alternative_names:
                    request_params['SubjectAlternativeNames'] = subject_alternative_names

                response = acm.request_certificate(**request_params)
                certificate_arn = response['CertificateArn']

                # Validate the new certificate
                validation_options = get_validation_records(acm, certificate_arn)
                route53 = assume_role(validation_role_arn)
                upsert_validation_records(route53, hosted_zone_id, validation_options)

                try:
                    wait_for_issued(acm, certificate_arn, validation_timeout)
                except Exception as e:
                    print(f'Validation failed, cleaning up: {str(e)}')
                    delete_validation_records(route53, hosted_zone_id, validation_options)
                    try:
                        acm.delete_certificate(CertificateArn=certificate_arn)
                    except Exception as cleanup_err:
                        print(f'Warning: failed to delete certificate: {str(cleanup_err)}')
                    raise

                if cleanup_validation_records_flag:
                    delete_validation_records(route53, hosted_zone_id, validation_options)

                # Delete old certificate
                old_certificate_arn = physical_id
                if old_certificate_arn and old_certificate_arn != 'none':
                    try:
                        acm.delete_certificate(CertificateArn=old_certificate_arn)
                    except Exception as e:
                        print(f'Warning: failed to delete old certificate: {str(e)}')

                physical_id = certificate_arn
                send_response(event, context, 'SUCCESS', 'OK', physical_id, {
                    'CertificateArn': certificate_arn,
                })
            else:
                # No domain change — nothing to do, certificate is the same
                send_response(event, context, 'SUCCESS', 'OK', physical_id, {
                    'CertificateArn': physical_id,
                })

        elif event['RequestType'] == 'Delete':
            certificate_arn = physical_id
            if certificate_arn and certificate_arn != 'none':
                # Get validation records to clean up DNS
                try:
                    response = acm.describe_certificate(CertificateArn=certificate_arn)
                    validation_options = response['Certificate'].get('DomainValidationOptions', [])
                    route53 = assume_role(validation_role_arn)
                    delete_validation_records(route53, hosted_zone_id, validation_options)
                except Exception as e:
                    print(f'Warning: failed to clean up validation records: {str(e)}')

                # Delete the certificate
                try:
                    acm.delete_certificate(CertificateArn=certificate_arn)
                except Exception as e:
                    print(f'Warning: failed to delete certificate: {str(e)}')

            send_response(event, context, 'SUCCESS', 'OK', physical_id)

    except Exception as e:
        print(f'Error: {str(e)}')
        send_response(event, context, 'FAILED', str(e), physical_id)
