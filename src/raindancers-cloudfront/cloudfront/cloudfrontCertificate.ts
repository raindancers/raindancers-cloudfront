import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_route53 as route53,
  aws_iam as iam,
  aws_certificatemanager as acm,
  aws_lambda as lambda,
  aws_logs as logs,
  custom_resources as cr,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

/**
 * Properties for CloudFrontCertificate construct.
 */
export interface CloudFrontCertificateProps {
  /** Domain name for the certificate (e.g., 'example.com' or '*.example.com') */
  readonly domainName: string;
  /** Route53 hosted zone for DNS validation */
  readonly hostedZone: route53.IHostedZone;
  /** Optional subject alternative names */
  readonly subjectAlternativeNames?: string[];
}

/**
 * Creates an ACM certificate in us-east-1 for use with CloudFront.
 *
 * CloudFront requires certificates to be in us-east-1 region.
 * This construct uses a custom resource to create the certificate
 * in us-east-1 regardless of the stack's region.
 *
 * @example
 * ```typescript
 * const cert = new CloudFrontCertificate(this, 'Certificate', {
 *   domainName: 'example.com',
 *   hostedZone: zone,
 *   subjectAlternativeNames: ['*.example.com'],
 * });
 *
 * new cloudfront.Distribution(this, 'Distribution', {
 *   certificate: cert.certificate,
 *   domainNames: ['example.com'],
 *   // ...
 * });
 * ```
 */
export class CloudFrontCertificate extends constructs.Construct {
  /** The ACM certificate in us-east-1 */
  public readonly certificate: acm.ICertificate;

  constructor(scope: constructs.Construct, id: string, props: CloudFrontCertificateProps) {
    super(scope, id);

    const certLogGroup = new logs.LogGroup(this, 'CertificateFunctionLogGroup', {
      retention: logs.RetentionDays.ONE_WEEK,
    });

    const certFunction = new lambda.SingletonFunction(this, 'CertificateFunction', {
      uuid: 'cloudfront-certificate-us-east-1',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda', 'certificate')),
      timeout: core.Duration.minutes(15),
      logGroup: certLogGroup,
    });

    certFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'acm:RequestCertificate',
        'acm:DescribeCertificate',
        'acm:DeleteCertificate',
        'acm:AddTagsToCertificate',
      ],
      resources: ['*'],
    }));

    certFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'route53:GetChange',
        'route53:ListHostedZones',
      ],
      resources: ['*'],
    }));

    certFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'route53:ChangeResourceRecordSets',
      ],
      resources: [props.hostedZone.hostedZoneArn],
    }));

    const provider = new cr.Provider(this, 'CertificateProvider', {
      onEventHandler: certFunction,
    });

    const resource = new core.CustomResource(this, 'CertificateResource', {
      resourceType: 'Custom::CloudFrontCertificateInUsEast1',
      serviceToken: provider.serviceToken,
      properties: {
        DomainName: props.domainName,
        SubjectAlternativeNames: props.subjectAlternativeNames || [],
        HostedZoneId: props.hostedZone.hostedZoneId,
        Region: 'us-east-1',
      },
    });

    this.certificate = acm.Certificate.fromCertificateArn(
      this,
      'Certificate',
      resource.getAttString('CertificateArn'),
    );
  }
}
