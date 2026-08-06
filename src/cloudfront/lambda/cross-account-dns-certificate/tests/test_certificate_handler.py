import json
import sys
import os
import importlib
from unittest.mock import patch, MagicMock, call

# Ensure we import the correct index.py (certificate handler, not record handler)
handler_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, handler_dir)

# Force reimport in case the record handler's index was already cached
if 'index' in sys.modules:
    del sys.modules['index']

import index  # noqa: E402


def make_event(request_type, properties, old_properties=None, physical_id=None):
    event = {
        'RequestType': request_type,
        'StackId': 'arn:aws:cloudformation:us-east-1:123456789012:stack/test/guid',
        'RequestId': 'test-request-id',
        'LogicalResourceId': 'TestCertificate',
        'ResponseURL': 'https://cloudformation-custom-resource-response.s3.amazonaws.com/response',
        'ResourceProperties': properties,
    }
    if old_properties:
        event['OldResourceProperties'] = old_properties
    if physical_id:
        event['PhysicalResourceId'] = physical_id
    return event


def make_context():
    ctx = MagicMock()
    ctx.log_stream_name = 'test-log-stream'
    return ctx


def mock_describe_certificate_response(certificate_arn, status='PENDING_VALIDATION'):
    return {
        'Certificate': {
            'CertificateArn': certificate_arn,
            'Status': status,
            'DomainValidationOptions': [
                {
                    'DomainName': 'functionalself.com',
                    'ResourceRecord': {
                        'Name': '_abc123.functionalself.com',
                        'Type': 'CNAME',
                        'Value': '_xyz789.acm-validations.aws',
                    },
                },
                {
                    'DomainName': '*.functionalself.com',
                    'ResourceRecord': {
                        'Name': '_abc123.functionalself.com',
                        'Type': 'CNAME',
                        'Value': '_xyz789.acm-validations.aws',
                    },
                },
            ],
        },
    }


BASE_PROPS = {
    'DomainName': 'functionalself.com',
    'SubjectAlternativeNames': ['*.functionalself.com'],
    'HostedZoneId': 'Z03995881KZQGQM68KY17',
    'ValidationRoleArn': 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
    'ValidationTimeout': '60',
    'CleanupValidationRecords': 'true',
}


class TestUpsertValidationRecords:
    def test_constructs_valid_change_batch(self):
        mock_route53 = MagicMock()
        validation_options = [
            {
                'DomainName': 'functionalself.com',
                'ResourceRecord': {
                    'Name': '_abc123.functionalself.com',
                    'Type': 'CNAME',
                    'Value': '_xyz789.acm-validations.aws',
                },
            },
        ]

        index.upsert_validation_records(mock_route53, 'Z03995881KZQGQM68KY17', validation_options)

        mock_route53.change_resource_record_sets.assert_called_once()
        call_args = mock_route53.change_resource_record_sets.call_args[1]
        assert call_args['HostedZoneId'] == 'Z03995881KZQGQM68KY17'

        changes = call_args['ChangeBatch']['Changes']
        assert len(changes) == 1
        assert changes[0]['Action'] == 'UPSERT'
        assert changes[0]['ResourceRecordSet']['Name'] == '_abc123.functionalself.com'
        assert changes[0]['ResourceRecordSet']['Type'] == 'CNAME'
        assert changes[0]['ResourceRecordSet']['TTL'] == 300
        assert changes[0]['ResourceRecordSet']['ResourceRecords'] == [{'Value': '_xyz789.acm-validations.aws'}]

    def test_deduplicates_validation_records(self):
        mock_route53 = MagicMock()
        # Wildcard and apex often share the same validation record
        validation_options = [
            {
                'DomainName': 'functionalself.com',
                'ResourceRecord': {
                    'Name': '_abc123.functionalself.com',
                    'Type': 'CNAME',
                    'Value': '_xyz789.acm-validations.aws',
                },
            },
            {
                'DomainName': '*.functionalself.com',
                'ResourceRecord': {
                    'Name': '_abc123.functionalself.com',
                    'Type': 'CNAME',
                    'Value': '_xyz789.acm-validations.aws',
                },
            },
        ]

        index.upsert_validation_records(mock_route53, 'Z03995881KZQGQM68KY17', validation_options)

        call_args = mock_route53.change_resource_record_sets.call_args[1]
        changes = call_args['ChangeBatch']['Changes']
        # Only one CNAME even though two domains share it
        assert len(changes) == 1


class TestHandler:
    @patch.object(index.time, 'sleep', return_value=None)
    @patch.object(index.time, 'time')
    @patch('index.http')
    @patch('index.assume_role')
    @patch('index.boto3.client')
    def test_create_requests_certificate_and_validates(self, mock_boto_client, mock_assume_role, mock_http, mock_time, mock_sleep):
        cert_arn = 'arn:aws:acm:us-east-1:123456789012:certificate/abc-123'

        # time.time() returns increasing values so wait_for_issued doesn't timeout
        mock_time.side_effect = [0, 1, 2, 3, 4, 5]

        mock_acm = MagicMock()
        mock_boto_client.return_value = mock_acm
        mock_acm.request_certificate.return_value = {'CertificateArn': cert_arn}

        # First call returns validation records, second call returns ISSUED
        mock_acm.describe_certificate.side_effect = [
            mock_describe_certificate_response(cert_arn, 'PENDING_VALIDATION'),
            {'Certificate': {'CertificateArn': cert_arn, 'Status': 'ISSUED'}},
        ]

        mock_route53 = MagicMock()
        mock_assume_role.return_value = mock_route53

        event = make_event('Create', BASE_PROPS)
        index.handler(event, make_context())

        # Verify certificate was requested
        mock_acm.request_certificate.assert_called_once_with(
            DomainName='functionalself.com',
            ValidationMethod='DNS',
            SubjectAlternativeNames=['*.functionalself.com'],
        )

        # Verify role was assumed
        mock_assume_role.assert_called_with('arn:aws:iam::433041915837:role/hermes-dns-zone-delegation')

        # Verify validation records were created
        mock_route53.change_resource_record_sets.assert_called()

        # Verify SUCCESS response
        response_body = json.loads(mock_http.request.call_args[1]['body'].decode('utf-8'))
        assert response_body['Status'] == 'SUCCESS'
        assert response_body['PhysicalResourceId'] == cert_arn
        assert response_body['Data']['CertificateArn'] == cert_arn

    @patch.object(index.time, 'sleep', return_value=None)
    @patch.object(index.time, 'time')
    @patch('index.http')
    @patch('index.assume_role')
    @patch('index.boto3.client')
    def test_create_assumes_role_with_correct_arn(self, mock_boto_client, mock_assume_role, mock_http, mock_time, mock_sleep):
        cert_arn = 'arn:aws:acm:us-east-1:123456789012:certificate/abc-123'
        mock_time.side_effect = [0, 1, 2, 3, 4, 5]

        mock_acm = MagicMock()
        mock_boto_client.return_value = mock_acm
        mock_acm.request_certificate.return_value = {'CertificateArn': cert_arn}
        mock_acm.describe_certificate.side_effect = [
            mock_describe_certificate_response(cert_arn),
            {'Certificate': {'CertificateArn': cert_arn, 'Status': 'ISSUED'}},
        ]

        mock_route53 = MagicMock()
        mock_assume_role.return_value = mock_route53

        event = make_event('Create', BASE_PROPS)
        index.handler(event, make_context())

        mock_assume_role.assert_called_with('arn:aws:iam::433041915837:role/hermes-dns-zone-delegation')

    @patch.object(index.time, 'sleep', return_value=None)
    @patch('index.http')
    @patch('index.assume_role')
    @patch('index.boto3.client')
    def test_sts_access_denied_returns_failed(self, mock_boto_client, mock_assume_role, mock_http, mock_sleep):
        from botocore.exceptions import ClientError

        cert_arn = 'arn:aws:acm:us-east-1:123456789012:certificate/abc-123'

        mock_acm = MagicMock()
        mock_boto_client.return_value = mock_acm
        mock_acm.request_certificate.return_value = {'CertificateArn': cert_arn}
        mock_acm.describe_certificate.return_value = mock_describe_certificate_response(cert_arn)

        mock_assume_role.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Not authorized'}},
            'AssumeRole',
        )

        event = make_event('Create', BASE_PROPS)
        index.handler(event, make_context())

        response_body = json.loads(mock_http.request.call_args[1]['body'].decode('utf-8'))
        assert response_body['Status'] == 'FAILED'
        assert 'AccessDenied' in response_body['Reason']

    @patch.object(index.time, 'sleep', return_value=None)
    @patch.object(index.time, 'time')
    @patch('index.http')
    @patch('index.assume_role')
    @patch('index.boto3.client')
    def test_timeout_returns_failed_and_cleans_up(self, mock_boto_client, mock_assume_role, mock_http, mock_time, mock_sleep):
        cert_arn = 'arn:aws:acm:us-east-1:123456789012:certificate/abc-123'

        mock_acm = MagicMock()
        mock_boto_client.return_value = mock_acm
        mock_acm.request_certificate.return_value = {'CertificateArn': cert_arn}
        mock_acm.describe_certificate.return_value = mock_describe_certificate_response(cert_arn, 'PENDING_VALIDATION')

        mock_route53 = MagicMock()
        mock_assume_role.return_value = mock_route53

        # Simulate time passing beyond timeout (timeout is 10s)
        mock_time.side_effect = [0, 0, 100, 200]

        props = dict(BASE_PROPS)
        props['ValidationTimeout'] = '10'

        event = make_event('Create', props)
        index.handler(event, make_context())

        response_body = json.loads(mock_http.request.call_args[1]['body'].decode('utf-8'))
        assert response_body['Status'] == 'FAILED'
        assert 'not issued within' in response_body['Reason']

        # Should have attempted to delete the certificate on failure
        mock_acm.delete_certificate.assert_called_once_with(CertificateArn=cert_arn)

    @patch.object(index.time, 'sleep', return_value=None)
    @patch('index.http')
    @patch('index.assume_role')
    @patch('index.boto3.client')
    def test_delete_cleans_up_dns_and_certificate(self, mock_boto_client, mock_assume_role, mock_http, mock_sleep):
        cert_arn = 'arn:aws:acm:us-east-1:123456789012:certificate/abc-123'

        mock_acm = MagicMock()
        mock_boto_client.return_value = mock_acm
        mock_acm.describe_certificate.return_value = mock_describe_certificate_response(cert_arn, 'ISSUED')

        mock_route53 = MagicMock()
        mock_assume_role.return_value = mock_route53

        event = make_event('Delete', BASE_PROPS, physical_id=cert_arn)
        index.handler(event, make_context())

        # Should delete validation records
        mock_route53.change_resource_record_sets.assert_called_once()
        call_args = mock_route53.change_resource_record_sets.call_args[1]
        changes = call_args['ChangeBatch']['Changes']
        assert changes[0]['Action'] == 'DELETE'

        # Should delete the certificate
        mock_acm.delete_certificate.assert_called_once_with(CertificateArn=cert_arn)

        # Should return SUCCESS
        response_body = json.loads(mock_http.request.call_args[1]['body'].decode('utf-8'))
        assert response_body['Status'] == 'SUCCESS'
