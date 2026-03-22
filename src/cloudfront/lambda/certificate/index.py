import json
import boto3
import time
from typing import Any, Dict

acm = boto3.client('acm', region_name='us-east-1')
route53 = boto3.client('route53')

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Custom resource handler for creating ACM certificates in us-east-1.
    """
    print(f"Event: {json.dumps(event)}")
    
    try:
        request_type = event['RequestType']
        props = event['ResourceProperties']
        
        domain_name = props['DomainName']
        sans = props.get('SubjectAlternativeNames', [])
        hosted_zone_id = props['HostedZoneId']
        
        print(f"Processing {request_type} for domain: {domain_name}")
        print(f"Hosted Zone ID: {hosted_zone_id}")
        
        if request_type == 'Create':
            return create_certificate(domain_name, sans, hosted_zone_id)
        elif request_type == 'Update':
            # For updates, delete old and create new
            old_props = event['OldResourceProperties']
            old_cert_arn = event['PhysicalResourceId']
            
            # Create new certificate first
            result = create_certificate(domain_name, sans, hosted_zone_id)
            
            # Delete old certificate (best effort)
            try:
                acm.delete_certificate(CertificateArn=old_cert_arn)
            except Exception as e:
                print(f"Failed to delete old certificate: {e}")
            
            return result
        elif request_type == 'Delete':
            cert_arn = event['PhysicalResourceId']
            return delete_certificate(cert_arn, hosted_zone_id)
        
        return {
            'PhysicalResourceId': event.get('PhysicalResourceId', 'unknown'),
            'Data': {}
        }
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        raise

def create_certificate(domain_name: str, sans: list, hosted_zone_id: str) -> Dict[str, Any]:
    """Create and validate an ACM certificate."""
    
    # Request certificate
    request_params = {
        'DomainName': domain_name,
        'ValidationMethod': 'DNS',
    }
    
    if sans:
        request_params['SubjectAlternativeNames'] = sans
    
    response = acm.request_certificate(**request_params)
    cert_arn = response['CertificateArn']
    
    print(f"Certificate requested: {cert_arn}")
    
    # Wait for validation records to be available
    validation_records = wait_for_validation_records(cert_arn)
    
    # Create DNS validation records
    create_validation_records(validation_records, hosted_zone_id)
    
    # Wait for certificate to be issued
    wait_for_certificate_validation(cert_arn)
    
    return {
        'PhysicalResourceId': cert_arn,
        'Data': {
            'CertificateArn': cert_arn
        }
    }

def delete_certificate(cert_arn: str, hosted_zone_id: str) -> Dict[str, Any]:
    """Delete certificate and cleanup validation records."""
    
    try:
        # Get validation records before deleting
        cert = acm.describe_certificate(CertificateArn=cert_arn)
        validation_records = cert['Certificate'].get('DomainValidationOptions', [])
        
        # Delete validation records
        delete_validation_records(validation_records, hosted_zone_id)
        
        # Delete certificate
        acm.delete_certificate(CertificateArn=cert_arn)
        print(f"Certificate deleted: {cert_arn}")
    except acm.exceptions.ResourceNotFoundException:
        print(f"Certificate not found: {cert_arn}")
    except Exception as e:
        print(f"Error deleting certificate: {e}")
    
    return {
        'PhysicalResourceId': cert_arn,
        'Data': {}
    }

def wait_for_validation_records(cert_arn: str, max_attempts: int = 60) -> list:
    """Wait for validation records to be available."""
    
    for attempt in range(max_attempts):
        cert = acm.describe_certificate(CertificateArn=cert_arn)
        validation_options = cert['Certificate'].get('DomainValidationOptions', [])
        
        # Check if all domains have validation records
        all_ready = all(
            'ResourceRecord' in option 
            for option in validation_options
        )
        
        if all_ready:
            return validation_options
        
        time.sleep(5)
    
    raise Exception("Timeout waiting for validation records")

def create_validation_records(validation_options: list, hosted_zone_id: str) -> None:
    """Create DNS validation records in Route53."""
    
    changes = []
    for option in validation_options:
        if 'ResourceRecord' in option:
            record = option['ResourceRecord']
            print(f"Creating validation record: {record['Name']} -> {record['Value']}")
            changes.append({
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': record['Name'],
                    'Type': record['Type'],
                    'TTL': 300,
                    'ResourceRecords': [{'Value': record['Value']}]
                }
            })
    
    if changes:
        print(f"Applying {len(changes)} DNS changes to hosted zone {hosted_zone_id}")
        response = route53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={'Changes': changes}
        )
        
        # Wait for change to propagate
        change_id = response['ChangeInfo']['Id']
        print(f"Waiting for Route53 change {change_id} to complete")
        wait_for_route53_change(change_id)
        print(f"Route53 change completed")
    else:
        print("No validation records to create")

def delete_validation_records(validation_options: list, hosted_zone_id: str) -> None:
    """Delete DNS validation records from Route53."""
    
    changes = []
    for option in validation_options:
        if 'ResourceRecord' in option:
            record = option['ResourceRecord']
            changes.append({
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': record['Name'],
                    'Type': record['Type'],
                    'TTL': 300,
                    'ResourceRecords': [{'Value': record['Value']}]
                }
            })
    
    if changes:
        try:
            route53.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={'Changes': changes}
            )
        except Exception as e:
            print(f"Error deleting validation records: {e}")

def wait_for_route53_change(change_id: str, max_attempts: int = 60) -> None:
    """Wait for Route53 change to complete."""
    
    for attempt in range(max_attempts):
        response = route53.get_change(Id=change_id)
        if response['ChangeInfo']['Status'] == 'INSYNC':
            return
        time.sleep(5)
    
    raise Exception("Timeout waiting for Route53 change")

def wait_for_certificate_validation(cert_arn: str, max_attempts: int = 120) -> None:
    """Wait for certificate to be validated and issued."""
    
    for attempt in range(max_attempts):
        cert = acm.describe_certificate(CertificateArn=cert_arn)
        status = cert['Certificate']['Status']
        
        if status == 'ISSUED':
            print(f"Certificate issued: {cert_arn}")
            return
        elif status == 'FAILED':
            raise Exception(f"Certificate validation failed: {cert_arn}")
        
        time.sleep(10)
    
    raise Exception("Timeout waiting for certificate validation")
