import json
import sys
import os
import importlib
from unittest.mock import patch, MagicMock

# Ensure we import the correct index.py (record handler)
handler_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, handler_dir)

# Force reimport to get the record handler's index module
if 'index' in sys.modules:
    del sys.modules['index']

import index  # noqa: E402


def make_event(request_type, properties, old_properties=None, physical_id=None):
    event = {
        'RequestType': request_type,
        'StackId': 'arn:aws:cloudformation:us-east-1:123456789012:stack/test/guid',
        'RequestId': 'test-request-id',
        'LogicalResourceId': 'TestRecord',
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


class TestBuildChangeBatch:
    def test_alias_record_upsert(self):
        props = {
            'RecordName': 'example.com',
            'RecordType': 'A',
            'AliasTarget': {
                'DNSName': 'd123.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
                'EvaluateTargetHealth': 'false',
            },
        }
        result = index.build_change_batch('UPSERT', props)

        assert result['Changes'][0]['Action'] == 'UPSERT'
        rrs = result['Changes'][0]['ResourceRecordSet']
        assert rrs['Name'] == 'example.com'
        assert rrs['Type'] == 'A'
        assert rrs['AliasTarget']['DNSName'] == 'd123.cloudfront.net'
        assert rrs['AliasTarget']['HostedZoneId'] == 'Z2FDTNDATAQYW2'
        assert rrs['AliasTarget']['EvaluateTargetHealth'] is False

    def test_alias_record_aaaa(self):
        props = {
            'RecordName': 'example.com',
            'RecordType': 'AAAA',
            'AliasTarget': {
                'DNSName': 'd123.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
                'EvaluateTargetHealth': 'true',
            },
        }
        result = index.build_change_batch('UPSERT', props)

        rrs = result['Changes'][0]['ResourceRecordSet']
        assert rrs['Type'] == 'AAAA'
        assert rrs['AliasTarget']['EvaluateTargetHealth'] is True

    def test_non_alias_record_with_ttl(self):
        props = {
            'RecordName': 'mail.example.com',
            'RecordType': 'MX',
            'ResourceRecords': ['10 mail.example.com'],
            'TTL': '600',
        }
        result = index.build_change_batch('UPSERT', props)

        rrs = result['Changes'][0]['ResourceRecordSet']
        assert rrs['Name'] == 'mail.example.com'
        assert rrs['Type'] == 'MX'
        assert rrs['TTL'] == 600
        assert rrs['ResourceRecords'] == [{'Value': '10 mail.example.com'}]

    def test_non_alias_record_default_ttl(self):
        props = {
            'RecordName': 'test.example.com',
            'RecordType': 'CNAME',
            'ResourceRecords': ['target.example.com'],
        }
        result = index.build_change_batch('UPSERT', props)

        rrs = result['Changes'][0]['ResourceRecordSet']
        assert rrs['TTL'] == 300

    def test_delete_action(self):
        props = {
            'RecordName': 'example.com',
            'RecordType': 'A',
            'AliasTarget': {
                'DNSName': 'd123.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
            },
        }
        result = index.build_change_batch('DELETE', props)
        assert result['Changes'][0]['Action'] == 'DELETE'


class TestHandler:
    @patch.object(index, 'http')
    @patch.object(index, 'assume_role')
    def test_create_alias_record(self, mock_assume_role, mock_http):
        mock_route53 = MagicMock()
        mock_assume_role.return_value = mock_route53

        props = {
            'HostedZoneId': 'Z03995881KZQGQM68KY17',
            'RoleArn': 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
            'RecordName': 'functionalself.com',
            'RecordType': 'A',
            'AliasTarget': {
                'DNSName': 'd123.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
                'EvaluateTargetHealth': 'false',
            },
        }

        event = make_event('Create', props)
        index.handler(event, make_context())

        mock_assume_role.assert_called_once_with('arn:aws:iam::433041915837:role/hermes-dns-zone-delegation')
        mock_route53.change_resource_record_sets.assert_called_once()

        call_args = mock_route53.change_resource_record_sets.call_args
        assert call_args[1]['HostedZoneId'] == 'Z03995881KZQGQM68KY17'

        # Verify response sent with SUCCESS
        response_body = json.loads(mock_http.request.call_args[1]['body'].decode('utf-8'))
        assert response_body['Status'] == 'SUCCESS'
        assert response_body['PhysicalResourceId'] == 'Z03995881KZQGQM68KY17/functionalself.com/A'

    @patch.object(index, 'http')
    @patch.object(index, 'assume_role')
    def test_physical_resource_id_format(self, mock_assume_role, mock_http):
        mock_route53 = MagicMock()
        mock_assume_role.return_value = mock_route53

        props = {
            'HostedZoneId': 'ZABC123',
            'RoleArn': 'arn:aws:iam::111111111111:role/test-role',
            'RecordName': 'sub.example.com',
            'RecordType': 'AAAA',
            'AliasTarget': {
                'DNSName': 'd456.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
            },
        }

        event = make_event('Create', props)
        index.handler(event, make_context())

        response_body = json.loads(mock_http.request.call_args[1]['body'].decode('utf-8'))
        assert response_body['PhysicalResourceId'] == 'ZABC123/sub.example.com/AAAA'

    @patch.object(index, 'http')
    @patch.object(index, 'assume_role')
    def test_delete_calls_route53(self, mock_assume_role, mock_http):
        mock_route53 = MagicMock()
        mock_assume_role.return_value = mock_route53

        props = {
            'HostedZoneId': 'Z03995881KZQGQM68KY17',
            'RoleArn': 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
            'RecordName': 'functionalself.com',
            'RecordType': 'A',
            'AliasTarget': {
                'DNSName': 'd123.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
            },
        }

        event = make_event('Delete', props, physical_id='Z03995881KZQGQM68KY17/functionalself.com/A')
        index.handler(event, make_context())

        call_args = mock_route53.change_resource_record_sets.call_args
        change_batch = call_args[1]['ChangeBatch']
        assert change_batch['Changes'][0]['Action'] == 'DELETE'

        response_body = json.loads(mock_http.request.call_args[1]['body'].decode('utf-8'))
        assert response_body['Status'] == 'SUCCESS'

    @patch.object(index, 'http')
    @patch.object(index, 'assume_role')
    def test_update_with_name_change_deletes_old(self, mock_assume_role, mock_http):
        mock_route53 = MagicMock()
        mock_assume_role.return_value = mock_route53

        old_props = {
            'HostedZoneId': 'ZABC123',
            'RoleArn': 'arn:aws:iam::111111111111:role/test-role',
            'RecordName': 'old.example.com',
            'RecordType': 'A',
            'AliasTarget': {
                'DNSName': 'd123.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
            },
        }

        new_props = {
            'HostedZoneId': 'ZABC123',
            'RoleArn': 'arn:aws:iam::111111111111:role/test-role',
            'RecordName': 'new.example.com',
            'RecordType': 'A',
            'AliasTarget': {
                'DNSName': 'd123.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
            },
        }

        event = make_event('Update', new_props, old_properties=old_props, physical_id='ZABC123/old.example.com/A')
        index.handler(event, make_context())

        # Should be called twice: DELETE old, UPSERT new
        assert mock_route53.change_resource_record_sets.call_count == 2
        calls = mock_route53.change_resource_record_sets.call_args_list

        delete_batch = calls[0][1]['ChangeBatch']
        assert delete_batch['Changes'][0]['Action'] == 'DELETE'
        assert delete_batch['Changes'][0]['ResourceRecordSet']['Name'] == 'old.example.com'

        upsert_batch = calls[1][1]['ChangeBatch']
        assert upsert_batch['Changes'][0]['Action'] == 'UPSERT'
        assert upsert_batch['Changes'][0]['ResourceRecordSet']['Name'] == 'new.example.com'

    @patch.object(index, 'http')
    @patch.object(index, 'assume_role')
    def test_sts_access_denied_returns_failed(self, mock_assume_role, mock_http):
        from botocore.exceptions import ClientError
        mock_assume_role.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Not authorized'}},
            'AssumeRole',
        )

        props = {
            'HostedZoneId': 'ZABC123',
            'RoleArn': 'arn:aws:iam::111111111111:role/test-role',
            'RecordName': 'example.com',
            'RecordType': 'A',
            'AliasTarget': {
                'DNSName': 'd123.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
            },
        }

        event = make_event('Create', props)
        index.handler(event, make_context())

        response_body = json.loads(mock_http.request.call_args[1]['body'].decode('utf-8'))
        assert response_body['Status'] == 'FAILED'
        assert 'AccessDenied' in response_body['Reason']

    @patch.object(index, 'http')
    @patch.object(index, 'assume_role')
    def test_evaluate_target_health_false(self, mock_assume_role, mock_http):
        mock_route53 = MagicMock()
        mock_assume_role.return_value = mock_route53

        props = {
            'HostedZoneId': 'ZABC123',
            'RoleArn': 'arn:aws:iam::111111111111:role/test-role',
            'RecordName': 'example.com',
            'RecordType': 'A',
            'AliasTarget': {
                'DNSName': 'd123.cloudfront.net',
                'HostedZoneId': 'Z2FDTNDATAQYW2',
                'EvaluateTargetHealth': 'false',
            },
        }

        event = make_event('Create', props)
        index.handler(event, make_context())

        call_args = mock_route53.change_resource_record_sets.call_args
        alias_target = call_args[1]['ChangeBatch']['Changes'][0]['ResourceRecordSet']['AliasTarget']
        assert alias_target['EvaluateTargetHealth'] is False
