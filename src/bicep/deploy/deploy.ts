import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_iam as iam,
  aws_s3 as s3,
} from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as constructs from 'constructs';

export interface AzureFederatedCredentials {
  readonly clientId: string;
  readonly tenantId: string;
  readonly subscriptionId: string;
  readonly lambdaRoleName: string;
  readonly spObjectId: string;
}

export interface FunctionCodeProps {
  readonly s3BucketName: string;
  readonly s3ObjectKey: string;
}

export interface BicepDeploymentProps {
  readonly template: string;
  readonly parameters?: Record<string, string>;
  readonly azureFederatedCredentials: AzureFederatedCredentials;
  readonly resourceGroupName: string;
  readonly deploymentName?: string;
  readonly cloudformationStackArn?: string;
  readonly functionCode?: FunctionCodeProps;
}

/**
 * Deploys Azure Bicep templates via CloudFormation Custom Resource.
 *
 * This construct uses a Docker-based Lambda function because Azure CLI and Bicep
 * exceed Lambda's 250MB deployment package limit (~170MB combined). Docker Lambda
 * provides a 10GB image size limit, allowing us to pre-install Azure CLI and Bicep
 * in the container image.
 *
 * The Lambda executes `az deployment group create` to deploy Bicep templates and
 * returns outputs to CloudFormation, enabling atomic multi-cloud deployments where
 * AWS resources can depend on Azure resources within a single CDK stack.
 *
 * For simple Azure AD operations (app registrations, etc.), consider using the
 * SOP (Standard Operating Procedure) pattern instead, which makes direct Graph API
 * calls without requiring Azure CLI or Docker.
 */
export class BicepDeployment extends constructs.Construct {
  public readonly customResource: core.CustomResource;
  public readonly outputs: Record<string, string>;
  public readonly lambdaRole: iam.IRole;

  constructor(scope: constructs.Construct, id: string, props: BicepDeploymentProps) {
    super(scope, id);

    const deploymentName = props.deploymentName || `cdk-${id}`;
    const bicepDir = 'cdk.out/bicep';
    if (!fs.existsSync(bicepDir)) {
      fs.mkdirSync(bicepDir, { recursive: true });
    }
    fs.writeFileSync(`${bicepDir}/${deploymentName}.bicep`, props.template);

    // Create Lambda role with predictable name if specified
    let lambdaRole: iam.IRole | undefined;
    if (props.azureFederatedCredentials.lambdaRoleName) {
      lambdaRole = new iam.Role(this, 'LambdaRole', {
        roleName: props.azureFederatedCredentials.lambdaRoleName,
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
        ],
        inlinePolicies: {
          STSPolicy: new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: ['sts:GetWebIdentityToken'],
                resources: ['*'],
              }),
            ],
          }),
        },
      });
    }

    const handler = new lambda.DockerImageFunction(this, 'Handler', {
      code: lambda.DockerImageCode.fromImageAsset(path.join(__dirname, 'lambda')),
      timeout: core.Duration.minutes(15),
      memorySize: 512,
      role: lambdaRole,
    });

    this.lambdaRole = handler.role!;

    if (props.functionCode) {
      const assetBucket = s3.Bucket.fromBucketName(this, 'AssetBucket', props.functionCode.s3BucketName);
      assetBucket.grantRead(handler);
    }

    this.customResource = new core.CustomResource(this, 'Resource', {
      resourceType: 'Custom::BicepDeployment',
      serviceToken: handler.functionArn,
      properties: {
        TemplateFile: props.template,
        Parameters: JSON.stringify(props.parameters || {}),
        AzureClientId: props.azureFederatedCredentials.clientId,
        AzureTenantId: props.azureFederatedCredentials.tenantId,
        AzureSubscriptionId: props.azureFederatedCredentials.subscriptionId,
        ResourceGroupName: props.resourceGroupName,
        DeploymentName: deploymentName,
        FunctionCodeS3Bucket: props.functionCode?.s3BucketName,
        FunctionCodeS3Key: props.functionCode?.s3ObjectKey,
      },
    });

    this.outputs = {};
  }

  public getOutput(key: string): string {
    return this.customResource.getAttString(key);
  }
}
