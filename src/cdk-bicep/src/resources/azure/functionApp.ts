import { AppServicePlan } from './appServicePlan';
import { ManagedIdentity } from './managedIdentity';
import { StorageAccount } from './storageAccount';
import { ApplicationInsights } from './applicationInsights';
import { BicepTemplate } from '../../deploy/template';
import { BicepConstruct } from '../graph/bicepConstruct';

export interface FunctionAppProps {
  readonly name: string;
  readonly managedIdentity: ManagedIdentity;
  readonly appServicePlan: AppServicePlan;
  readonly storageAccount: StorageAccount;
  readonly applicationInsights?: ApplicationInsights;
}

export class FunctionApp extends BicepConstruct {
  public readonly name: string;
  public readonly defaultHostName: string;

  constructor(template: BicepTemplate, resourceName: string, private props: FunctionAppProps) {
    super(template, resourceName);
    const pascalName = this.toPascalCase(resourceName);
    this.name = `${pascalName}.name`;
    this.defaultHostName = `${pascalName}.properties.defaultHostName`;
  }

  synthesize(): void {
    const managedIdentityIdRef = `\${${this.props.managedIdentity.id}}`;
    
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Web/sites',
      apiVersion: '2022-09-01',
      name: this.props.name,
      location: 'location',
      kind: 'functionapp,linux',
      identity: {
        type: 'UserAssigned',
        userAssignedIdentities: {
          [managedIdentityIdRef]: {},
        },
      },
      properties: {
        serverFarmId: this.props.appServicePlan.id,
        siteConfig: {
          linuxFxVersion: 'Python|3.12',
          appSettings: [
            {
              name: 'AzureWebJobsStorage',
              value: `'DefaultEndpointsProtocol=https;AccountName=\${${this.props.storageAccount.name}};EndpointSuffix=\${environment().suffixes.storage};AccountKey=\${${this.toPascalCase(this.props.storageAccount.getResourceName())}.listKeys().keys[0].value}'`,
            },
            { name: 'FUNCTIONS_EXTENSION_VERSION', value: "'~4'" },
            { name: 'FUNCTIONS_WORKER_RUNTIME', value: "'python'" },
            { name: 'AZURE_CLIENT_ID', value: this.props.managedIdentity.clientId },
            { name: 'AzureWebJobsFeatureFlags', value: "'EnableWorkerIndexing'" },
            ...(this.props.applicationInsights ? [{
              name: 'APPLICATIONINSIGHTS_CONNECTION_STRING',
              value: this.props.applicationInsights.connectionString,
            }] : []),
          ],
          ftpsState: 'Disabled',
          minTlsVersion: '1.2',
        },
        httpsOnly: true,
      },
    });
  }
}
