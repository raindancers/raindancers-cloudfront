import * as fs from 'fs';
import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_s3_assets as s3assets,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as bicep from '../deploy';
import * as azure from '../resources/azure';
import * as graph from '../resources/graph';

/**
 * Well-known OIDC audience values for common providers
 */
export enum OidcAudience {
  /** AWS Security Token Service */
  AWS_STS = 'sts.amazonaws.com',
  /** Azure AD Token Exchange for Workload Identity Federation */
  AZURE_AD_TOKEN_EXCHANGE = 'api://AzureADTokenExchange',
  /** Microsoft Graph API */
  MICROSOFT_GRAPH = 'https://graph.microsoft.com',
  /** Kubernetes default service account */
  KUBERNETES = 'https://kubernetes.default.svc',
}

/**
 * Configuration for external identity trusted to request tokens
 */
export interface TrustedTokenRequesterConfig {
  /** OIDC issuer URL that Azure AD trusts */
  readonly issuer: string;
  /** Subject (sub) claim identifying the trusted workload */
  readonly sub: string;
  /** Audience (aud) values for token validation - use OidcAudience enum or custom strings */
  readonly aud: string[];
}

/**
 * Properties for Azure AD application with federated credentials.
 */
export interface AzureAdApplicationFederatedProps {
  /** Name of the Azure AD application */
  readonly appName: string;
  /** Redirect URIs for OAuth callbacks */
  readonly redirectUris: string[];
  /** Supported account types for sign-in (defaults to single tenant) */
  readonly signInAudience?: graph.SignInAudience;
  /** Azure resource group name */
  readonly resourceGroupName: string;
  /** Azure AD groups to create */
  readonly groups?: string[];
  /** Azure federated credentials for deployment */
  readonly deploymentCredentials: bicep.AzureFederatedCredentials;
  /** External identity trusted to request tokens */
  readonly trustedTokenRequester: TrustedTokenRequesterConfig;
  /** Enable AWS session tag mapping via Custom Claims Provider (requires groups to be defined) */
  readonly enableAwsSessionTagMapping?: boolean;
}

export class AzureAdApplicationFederated extends Construct {
  /** All deployment outputs */
  public readonly outputs: Record<string, string>;
  /** Trusted token requester configuration */
  public readonly trustedTokenRequester: TrustedTokenRequesterConfig;

  constructor(scope: Construct, id: string, props: AzureAdApplicationFederatedProps) {
    super(scope, id);

    if (props.enableAwsSessionTagMapping && (!props.groups || props.groups.length === 0)) {
      throw new Error(
        'enableAwsSessionTagMapping requires groups to be defined. ' +
        'Custom Claims Provider maps Azure AD groups/roles to AWS session tags.',
      );
    }

    this.trustedTokenRequester = props.trustedTokenRequester;

    const stack = core.Stack.of(this);
    const cloudformationArn = `arn:aws:cloudformation:${stack.region}:${stack.account}:stack/${stack.stackName}`;

    let claimsProviderResult: { functionCodeAsset: s3assets.Asset } | undefined;

    const { template, outputKeys } = new bicep.BicepTemplateBuilder()
      .withMetadata({
        name: props.appName,
        description: 'Azure AD Application with federated credentials for AWS integration',
        cloudformation: {
          stackArn: cloudformationArn,
        },
      })
      .withExtensions(bicep.BicepExtension.MICROSOFT_GRAPH_STABLE)
      .withResources(builder => {
        claimsProviderResult = this.buildResources(builder, props);
      })
      .withOutputs({
        appId: 'Application.appId',
        tenantId: 'tenant().tenantId',
        ...(props.enableAwsSessionTagMapping ? {
          functionAppName: 'Functionapp.name',
        } : {}),
      })
      .build();

    const deployment = new bicep.BicepDeployment(this, 'Deployment', {
      template: template.synthesize(),
      resourceGroupName: props.resourceGroupName,
      azureFederatedCredentials: props.deploymentCredentials,
      cloudformationStackArn: cloudformationArn,
      parameters: {
        deploymentSpObjectId: props.deploymentCredentials.spObjectId,
      },
      functionCode: claimsProviderResult ? {
        s3BucketName: claimsProviderResult.functionCodeAsset.s3BucketName,
        s3ObjectKey: claimsProviderResult.functionCodeAsset.s3ObjectKey,
      } : undefined,
    });

    if (claimsProviderResult) {
      claimsProviderResult.functionCodeAsset.grantRead(deployment.lambdaRole);
    }

    this.outputs = {};
    outputKeys.forEach(key => {
      this.outputs[key] = deployment.getOutput(key);
    });
  }

  private buildResources(
    template: bicep.BicepTemplate,
    props: AzureAdApplicationFederatedProps,
  ): { functionCodeAsset: s3assets.Asset } | undefined {
    const appRoles = props.groups?.map((groupName) => {
      const roleId = `guid('${groupName}-role')`;
      return {
        id: roleId,
        displayName: groupName,
        description: `${groupName} role for ${props.appName}`,
        value: groupName,
        allowedMemberTypes: [graph.AllowedMemberType.USER],
        isEnabled: true,
      };
    }) || [];

    const application = new graph.Application(template, 'application', {
      displayName: props.appName,
      redirectUris: props.redirectUris,
      signInAudience: props.signInAudience ?? graph.SignInAudience.AZURE_AD_MY_ORG,
      appRoles: appRoles,
      optionalClaims: appRoles.length > 0 ? {
        idToken: [
          {
            name: 'roles',
            essential: false,
          },
          ...(props.enableAwsSessionTagMapping ? [{
            name: 'https://aws.amazon.com/tags/principal_tags/Roles',
            essential: false,
            source: 'customClaimsProvider',
          }] : []),
        ],
      } : undefined,
    });

    const servicePrincipal = new graph.ServicePrincipal(template, 'servicePrincipal', {
      application: application,
      appRoleAssignmentRequired: false,
    });

    const federatedCredential = new graph.FederatedIdentityCredential(template, 'federatedCredential', {
      application: application,
      name: `${props.appName}-aws-credential`,
      issuer: props.trustedTokenRequester.issuer,
      subject: props.trustedTokenRequester.sub,
      audiences: props.trustedTokenRequester.aud,
      description: `Federated credential for ${props.appName} AWS integration`,
    });

    if (props.groups) {
      props.groups.forEach((groupName) => {
        const sanitizedName = this.sanitizeIdentifier(groupName);

        const group = new graph.Group(template, `group${sanitizedName}`, {
          displayName: groupName,
          description: `${groupName} group for ${props.appName}`,
        });

        const appRoleId = `guid('${groupName}-role')`;

        const assignment = new graph.AppRoleAssignment(template, `groupAssignment${sanitizedName}`, {
          resourceServicePrincipal: servicePrincipal,
          principal: group,
          appRoleId: appRoleId,
        });

        group.synthesize();
        assignment.synthesize();
      });
    }

    application.synthesize();
    servicePrincipal.synthesize();
    federatedCredential.synthesize();

    if (!props.enableAwsSessionTagMapping) {
      return undefined;
    }

    return this.buildCustomClaimsProvider(template, props);
  }

  private buildCustomClaimsProvider(
    template: bicep.BicepTemplate,
    props: AzureAdApplicationFederatedProps,
  ): { functionCodeAsset: s3assets.Asset } {
    template.addStringParameter('location', 'Azure region for resources', "'australiaeast'");
    template.addStringParameter('deploymentSpObjectId', 'Object ID of the SP deploying this template (needs Storage Blob Data Contributor)', '');

    const namePrefix = props.appName.toLowerCase();
    const uniqueSuffix = 'substring(uniqueString(resourceGroup().id), 0, 8)';

    const managedIdentity = new azure.ManagedIdentity(template, 'managedIdentity', {
      name: `'${namePrefix}-claims-identity-\${${uniqueSuffix}}'`,
    });

    const storageAccount = new azure.StorageAccount(template, 'storageAccount', {
      name: `'${namePrefix}claims\${${uniqueSuffix}}'`,
    });

    const appServicePlan = new azure.AppServicePlan(template, 'appServicePlan', {
      name: `'${namePrefix}-claims-plan-\${${uniqueSuffix}}'`,
    });

    const logAnalyticsWorkspace = new azure.LogAnalyticsWorkspace(template, 'logAnalyticsWorkspace', {
      name: `'${namePrefix}-claims-logs-\${${uniqueSuffix}}'`,
    });

    const applicationInsights = new azure.ApplicationInsights(template, 'applicationInsights', {
      name: `'${namePrefix}-claims-insights-\${${uniqueSuffix}}'`,
      logAnalyticsWorkspace: logAnalyticsWorkspace,
    });

    const functionApp = new azure.FunctionApp(template, 'functionApp', {
      name: `'${namePrefix}-claims-func-\${${uniqueSuffix}}'`,
      managedIdentity: managedIdentity,
      appServicePlan: appServicePlan,
      storageAccount: storageAccount,
      applicationInsights: applicationInsights,
    });

    const roleAssignment = new azure.RoleAssignment(template, 'managedIdentityContributor', {
      name: `guid('${props.appName}-mi-contributor')`,
      roleDefinitionId: azure.AzureBuiltInRole.WEBSITE_CONTRIBUTOR,
      principalId: managedIdentity,
    });

    const spBlobRoleAssignment = new azure.RoleAssignment(template, 'deploymentSpBlobContributor', {
      name: `guid('${props.appName}-sp-blob-contributor')`,
      roleDefinitionId: azure.AzureBuiltInRole.STORAGE_BLOB_DATA_CONTRIBUTOR,
      principalId: 'deploymentSpObjectId',
    });
    spBlobRoleAssignment.addDependency(storageAccount);

    const functionCodeAsset = new s3assets.Asset(this, 'FunctionCodeAsset', {
      path: path.join(__dirname, '..', 'azure-functions', 'custom-claims-provider'),
      bundling: {
        image: core.DockerImage.fromRegistry('python:3.12-slim'),
        command: [
          'bash', '-c',
          'pip install -r /asset-input/requirements.txt -t /asset-output/ && cp /asset-input/function_app.py /asset-input/host.json /asset-input/requirements.txt /asset-output/',
        ],
      },
    });

    const functionAppRegistration = new graph.Application(template, 'functionAppRegistration', {
      displayName: `${namePrefix}-claims-func-app`,
      redirectUris: [],
      requiredResourceAccess: [
        {
          resourceAppId: graph.ResourceAppId.MICROSOFT_GRAPH,
          resourceAccess: [
            {
              id: graph.MicrosoftGraphPermission.CUSTOM_AUTH_EXT_RECEIVE_PAYLOAD,
              type: graph.PermissionType.ROLE,
            },
          ],
        },
      ],
    });

    const graphServicePrincipal = new graph.ExistingServicePrincipal(template, 'graphServicePrincipal', {
      appId: '00000003-0000-0000-c000-000000000000',
    });

    const miPolicyReadPermission = new graph.AppRoleAssignment(template, 'miPolicyReadPermission', {
      resourceServicePrincipal: graphServicePrincipal,
      principal: `${managedIdentity.principalId}`,
      appRoleId: '\'246dd0d5-5bd0-4def-940b-0421030a5b68\'',
    });

    const miPolicyPermission = new graph.AppRoleAssignment(template, 'miPolicyPermission', {
      resourceServicePrincipal: graphServicePrincipal,
      principal: `${managedIdentity.principalId}`,
      appRoleId: '\'be74164b-cff1-491c-8741-e671cb536e13\'',
    });

    const miCustomAuthExtPermission = new graph.AppRoleAssignment(template, 'miCustomAuthExtPermission', {
      resourceServicePrincipal: graphServicePrincipal,
      principal: `${managedIdentity.principalId}`,
      appRoleId: '\'c2667967-7050-4e7e-b059-4cbbb3811d03\'',
    });

    const miEventListenerPermission = new graph.AppRoleAssignment(template, 'miEventListenerPermission', {
      resourceServicePrincipal: graphServicePrincipal,
      principal: `${managedIdentity.principalId}`,
      appRoleId: '\'0edf5e9e-4ce8-468a-8432-d08631d18c43\'',
    });

    const miAppReadWritePermission = new graph.AppRoleAssignment(template, 'miAppReadWritePermission', {
      resourceServicePrincipal: graphServicePrincipal,
      principal: `${managedIdentity.principalId}`,
      appRoleId: `'${graph.MicrosoftGraphPermission.APPLICATION_READ_WRITE_ALL}'`,
    });

    const wireCustomClaimsExtension = new azure.DeploymentScript(template, 'wireCustomClaimsExtension', {
      name: "'wire-custom-claims-extension'",
      managedIdentity: managedIdentity,
      scriptContent: fs.readFileSync(path.join(__dirname, 'scripts', 'wire-custom-claims-extension.sh'), 'utf8'),
      environmentVariables: {
        FUNCTION_HOSTNAME: 'Functionapp.properties.defaultHostName',
        FUNCTION_APP_ID: 'Functionappregistration.appId',
        CLF_APP_ID: 'Application.appId',
        EXT_DISPLAY_NAME: `'${namePrefix}-claims-provider'`,
      },
    });
    wireCustomClaimsExtension.addDependency(miPolicyReadPermission);
    wireCustomClaimsExtension.addDependency(miPolicyPermission);
    wireCustomClaimsExtension.addDependency(miCustomAuthExtPermission);
    wireCustomClaimsExtension.addDependency(miEventListenerPermission);
    wireCustomClaimsExtension.addDependency(miAppReadWritePermission);

    managedIdentity.synthesize();
    storageAccount.synthesize();
    appServicePlan.synthesize();
    logAnalyticsWorkspace.synthesize();
    applicationInsights.synthesize();
    functionApp.synthesize();
    roleAssignment.synthesize();
    spBlobRoleAssignment.synthesize();
    functionAppRegistration.synthesize();
    graphServicePrincipal.synthesize();
    miPolicyReadPermission.synthesize();
    miPolicyPermission.synthesize();
    miCustomAuthExtPermission.synthesize();
    miEventListenerPermission.synthesize();
    miAppReadWritePermission.synthesize();
    wireCustomClaimsExtension.synthesize();

    return {
      functionCodeAsset: functionCodeAsset,
    };
  }

  private sanitizeIdentifier(name: string): string {
    return name
      .split(/[-_\s]+/)
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join('')
      .replace(/[^a-zA-Z0-9]/g, '')
      .replace(/^[0-9]/, '_$&');
  }
}
