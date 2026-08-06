import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_iam as iam,
  aws_lambda as lambda,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface CrossAccountDnsValidatedCertificateProps {
  readonly domainName: string;
  readonly subjectAlternativeNames?: string[];
  readonly hostedZoneId: string;
  readonly validationRoleArn: string;
  readonly validationTimeout?: core.Duration;
  readonly cleanupValidationRecords?: boolean;
  readonly certificateRegion?: string;
}

export class CrossAccountDnsValidatedCertificate extends constructs.Construct {

  public readonly certificateArn: string;

  private static readonly SINGLETON_KEY = 'CrossAccountDnsValidatedCertificateFunction';

  constructor(scope: constructs.Construct, id: string, props: CrossAccountDnsValidatedCertificateProps) {
    super(scope, id);

    const fn = this.getOrCreateFunction(props.validationRoleArn);

    const resourceProperties: Record<string, unknown> = {
      DomainName: props.domainName,
      HostedZoneId: props.hostedZoneId,
      ValidationRoleArn: props.validationRoleArn,
      CleanupValidationRecords: props.cleanupValidationRecords === false ? 'false' : 'true',
    };

    if (props.subjectAlternativeNames) {
      resourceProperties.SubjectAlternativeNames = props.subjectAlternativeNames;
    }

    if (props.validationTimeout) {
      resourceProperties.ValidationTimeout = props.validationTimeout.toSeconds().toString();
    }

    if (props.certificateRegion) {
      resourceProperties.CertificateRegion = props.certificateRegion;
    }

    const resource = new core.CustomResource(this, 'Resource', {
      serviceToken: fn.functionArn,
      resourceType: 'Custom::CrossAccountDnsValidatedCertificate',
      properties: resourceProperties,
    });

    this.certificateArn = resource.getAttString('CertificateArn');
  }

  private getOrCreateFunction(validationRoleArn: string): lambda.Function {
    const stack = core.Stack.of(this);
    const existing = stack.node.tryFindChild(CrossAccountDnsValidatedCertificate.SINGLETON_KEY);

    if (existing) {
      const fn = existing as lambda.Function;
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: ['sts:AssumeRole'],
        resources: [validationRoleArn],
      }));
      return fn;
    }

    const fn = new lambda.Function(stack, CrossAccountDnsValidatedCertificate.SINGLETON_KEY, {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      timeout: core.Duration.minutes(15),
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda/cross-account-dns-certificate')),
    });

    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'acm:RequestCertificate',
        'acm:DescribeCertificate',
        'acm:DeleteCertificate',
        'acm:ListCertificates',
      ],
      resources: ['*'],
    }));

    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['sts:AssumeRole'],
      resources: [validationRoleArn],
    }));

    return fn;
  }
}
