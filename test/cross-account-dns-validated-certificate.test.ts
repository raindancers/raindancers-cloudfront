import * as core from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { CrossAccountDnsValidatedCertificate } from '../src/cloudfront/crossAccountDnsValidatedCertificate';

describe('CrossAccountDnsValidatedCertificate', () => {
  let app: core.App;
  let stack: core.Stack;

  beforeEach(() => {
    app = new core.App();
    stack = new core.Stack(app, 'TestStack');
  });

  test('custom resource properties contain all required fields', () => {
    new CrossAccountDnsValidatedCertificate(stack, 'TestCert', {
      domainName: 'functionalself.com',
      subjectAlternativeNames: ['*.functionalself.com'],
      hostedZoneId: 'Z03995881KZQGQM68KY17',
      validationRoleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('Custom::CrossAccountDnsValidatedCertificate', {
      DomainName: 'functionalself.com',
      SubjectAlternativeNames: ['*.functionalself.com'],
      HostedZoneId: 'Z03995881KZQGQM68KY17',
      ValidationRoleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
      CleanupValidationRecords: 'true',
    });
  });

  test('Lambda function has ACM and sts:AssumeRole permissions', () => {
    new CrossAccountDnsValidatedCertificate(stack, 'TestCert', {
      domainName: 'functionalself.com',
      hostedZoneId: 'Z03995881KZQGQM68KY17',
      validationRoleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: [
              'acm:RequestCertificate',
              'acm:DescribeCertificate',
              'acm:DeleteCertificate',
              'acm:ListCertificates',
            ],
            Effect: 'Allow',
            Resource: '*',
          }),
          Match.objectLike({
            Action: 'sts:AssumeRole',
            Effect: 'Allow',
            Resource: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
          }),
        ]),
      },
    });
  });

  test('Lambda runtime is Python 3.12 with 15 minute timeout', () => {
    new CrossAccountDnsValidatedCertificate(stack, 'TestCert', {
      domainName: 'functionalself.com',
      hostedZoneId: 'Z03995881KZQGQM68KY17',
      validationRoleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'python3.12',
      Handler: 'index.handler',
      Timeout: 900,
    });
  });

  test('singleton Lambda is reused across multiple certificates', () => {
    new CrossAccountDnsValidatedCertificate(stack, 'Cert1', {
      domainName: 'example.com',
      hostedZoneId: 'ZABC123',
      validationRoleArn: 'arn:aws:iam::111111111111:role/dns-role',
    });

    new CrossAccountDnsValidatedCertificate(stack, 'Cert2', {
      domainName: 'other.com',
      hostedZoneId: 'ZDEF456',
      validationRoleArn: 'arn:aws:iam::111111111111:role/dns-role',
    });

    const template = Template.fromStack(stack);

    template.resourceCountIs('AWS::Lambda::Function', 1);
    template.resourceCountIs('Custom::CrossAccountDnsValidatedCertificate', 2);
  });

  test('validation timeout is passed when specified', () => {
    new CrossAccountDnsValidatedCertificate(stack, 'TestCert', {
      domainName: 'functionalself.com',
      hostedZoneId: 'Z03995881KZQGQM68KY17',
      validationRoleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
      validationTimeout: core.Duration.seconds(600),
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('Custom::CrossAccountDnsValidatedCertificate', {
      ValidationTimeout: '600',
    });
  });

  test('certificate region is passed when specified', () => {
    new CrossAccountDnsValidatedCertificate(stack, 'TestCert', {
      domainName: 'functionalself.com',
      hostedZoneId: 'Z03995881KZQGQM68KY17',
      validationRoleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
      certificateRegion: 'us-east-1',
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('Custom::CrossAccountDnsValidatedCertificate', {
      CertificateRegion: 'us-east-1',
    });
  });

  test('cleanup validation records defaults to true', () => {
    new CrossAccountDnsValidatedCertificate(stack, 'TestCert', {
      domainName: 'functionalself.com',
      hostedZoneId: 'Z03995881KZQGQM68KY17',
      validationRoleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('Custom::CrossAccountDnsValidatedCertificate', {
      CleanupValidationRecords: 'true',
    });
  });

  test('cleanup validation records can be disabled', () => {
    new CrossAccountDnsValidatedCertificate(stack, 'TestCert', {
      domainName: 'functionalself.com',
      hostedZoneId: 'Z03995881KZQGQM68KY17',
      validationRoleArn: 'arn:aws:iam::433041915837:role/hermes-dns-zone-delegation',
      cleanupValidationRecords: false,
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('Custom::CrossAccountDnsValidatedCertificate', {
      CleanupValidationRecords: 'false',
    });
  });
});
