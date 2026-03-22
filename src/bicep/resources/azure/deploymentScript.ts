import { ManagedIdentity } from './managedIdentity';
import { BicepTemplate } from '../../deploy/template';
import { BicepConstruct } from '../graph/bicepConstruct';

export interface DeploymentScriptProps {
  readonly name: string;
  readonly managedIdentity: ManagedIdentity;
  readonly scriptContent: string;
  readonly forceUpdateTag?: string;
  readonly environmentVariables?: Record<string, string>;
  readonly secureEnvironmentVariables?: Record<string, string>;
}

export class DeploymentScript extends BicepConstruct {
  constructor(template: BicepTemplate, resourceName: string, public readonly props: DeploymentScriptProps) {
    super(template, resourceName);
  }

  synthesize(): void {
    const envVars = this.props.environmentVariables || {};
    const secureEnvVars = this.props.secureEnvironmentVariables || {};

    const envList = [
      ...Object.entries(envVars).map(([name, value]) => ({ name: `'${name}'`, value: value })),
      ...Object.entries(secureEnvVars).map(([name, value]) => ({ name: `'${name}'`, secureValue: value })),
    ];

    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Resources/deploymentScripts',
      apiVersion: '2023-08-01',
      name: this.props.name,
      location: 'location',
      kind: 'AzureCLI',
      identity: {
        type: 'UserAssigned',
        userAssignedIdentities: {
          [`'\${${this.props.managedIdentity.id}}'`]: {},
        },
      },
      properties: {
        azCliVersion: "'2.67.0'",
        retentionInterval: "'PT1H'",
        timeout: "'PT10M'",
        cleanupPreference: "'OnExpiration'",
        forceUpdateTag: this.props.forceUpdateTag,
        scriptContent: this.props.scriptContent,
        environmentVariables: envList.length > 0 ? envList : undefined,
      },
      dependsOn: this.explicitDependencies.length > 0 ? this.explicitDependencies : undefined,
    });
  }
}
