import * as core from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { CrossAccountRoute53Record } from '../src/cloudfront/crossAccountRoute53Record';

describe('CrossAccountRoute53Record', () => {
  let app: core.App;
  let stack: core.Stack;

  beforeEach(() => {
    app = new core.App();
    stack = new core.Stack(app, 'TestStack');
  });

  test('custom resource properties contain all required fields for alias record', () => {
    new CrossAccountRoute53Record(stack, 'TestRecord', {
      hostedZoneId: 'Z03995881KZQGQM68KY17',
      roleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
      recordName: 'functionalself.com',
      recordType: 'A',
      aliasTarget: {
        dnsName: 'd123.cloudfront.net',
        hostedZoneId: 'Z2FDTNDATAQYW2',
        evaluateTargetHealth: false,
      },
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::CloudFormation::CustomResource', {
      HostedZoneId: 'Z03995881KZQGQM68KY17',
      RoleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
      RecordName: 'functionalself.com',
      RecordType: 'A',
      AliasTarget: {
        DNSName: 'd123.cloudfront.net',
        HostedZoneId: 'Z2FDTNDATAQYW2',
        EvaluateTargetHealth: 'false',
      },
    });
  });

  test('Lambda function has sts:AssumeRole permission on the role ARN', () => {
    new CrossAccountRoute53Record(stack, 'TestRecord', {
      hostedZoneId: 'Z03995881KZQGQM68KY17',
      roleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
      recordName: 'functionalself.com',
      recordType: 'A',
      aliasTarget: {
        dnsName: 'd123.cloudfront.net',
        hostedZoneId: 'Z2FDTNDATAQYW2',
      },
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 'sts:AssumeRole',
            Effect: 'Allow',
            Resource: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
          }),
        ]),
      },
    });
  });

  test('Lambda runtime is Python 3.12', () => {
    new CrossAccountRoute53Record(stack, 'TestRecord', {
      hostedZoneId: 'ZABC123',
      roleArn: 'arn:aws:iam::111111111111:role/test-role',
      recordName: 'example.com',
      recordType: 'A',
      aliasTarget: {
        dnsName: 'd123.cloudfront.net',
        hostedZoneId: 'Z2FDTNDATAQYW2',
      },
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'python3.12',
      Handler: 'index.handler',
      Timeout: 30,
    });
  });

  test('singleton Lambda is reused across multiple records', () => {
    new CrossAccountRoute53Record(stack, 'Record1', {
      hostedZoneId: 'ZABC123',
      roleArn: 'arn:aws:iam::111111111111:role/test-role',
      recordName: 'a.example.com',
      recordType: 'A',
      aliasTarget: {
        dnsName: 'd123.cloudfront.net',
        hostedZoneId: 'Z2FDTNDATAQYW2',
      },
    });

    new CrossAccountRoute53Record(stack, 'Record2', {
      hostedZoneId: 'ZABC123',
      roleArn: 'arn:aws:iam::111111111111:role/test-role',
      recordName: 'b.example.com',
      recordType: 'AAAA',
      aliasTarget: {
        dnsName: 'd123.cloudfront.net',
        hostedZoneId: 'Z2FDTNDATAQYW2',
      },
    });

    const template = Template.fromStack(stack);

    // Only one Lambda function should exist
    template.resourceCountIs('AWS::Lambda::Function', 1);
    // Two custom resources
    template.resourceCountIs('AWS::CloudFormation::CustomResource', 2);
  });

  test('throws if neither aliasTarget nor resourceRecords provided', () => {
    expect(() => {
      new CrossAccountRoute53Record(stack, 'BadRecord', {
        hostedZoneId: 'ZABC123',
        roleArn: 'arn:aws:iam::111111111111:role/test-role',
        recordName: 'example.com',
        recordType: 'A',
      });
    }).toThrow('Either aliasTarget or resourceRecords must be provided');
  });

  test('non-alias record passes resourceRecords and TTL', () => {
    new CrossAccountRoute53Record(stack, 'CnameRecord', {
      hostedZoneId: 'ZABC123',
      roleArn: 'arn:aws:iam::111111111111:role/test-role',
      recordName: 'www.example.com',
      recordType: 'CNAME',
      resourceRecords: ['target.example.com'],
      ttl: core.Duration.seconds(600),
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::CloudFormation::CustomResource', {
      RecordName: 'www.example.com',
      RecordType: 'CNAME',
      ResourceRecords: ['target.example.com'],
      TTL: '600',
    });
  });
});
