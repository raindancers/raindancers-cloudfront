import { ManagedIdentity } from './managedIdentity';
import { BicepTemplate } from '../../deploy/template';
import { BicepConstruct } from '../graph/bicepConstruct';

// Well-known Azure built-in role definition IDs
export const AzureBuiltInRole = {
  CONTRIBUTOR: 'b24988ac-6180-42a0-ab88-20f7382dd24c',
  WEBSITE_CONTRIBUTOR: 'de139f84-1756-47ae-9be6-808fbbe84772',
  STORAGE_BLOB_DATA_CONTRIBUTOR: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe',
} as const;

export interface RoleAssignmentProps {
  readonly name: string;
  readonly roleDefinitionId: string;
  readonly principalId: ManagedIdentity | string;
}

export class RoleAssignment extends BicepConstruct {
  constructor(template: BicepTemplate, resourceName: string, private props: RoleAssignmentProps) {
    super(template, resourceName);
  }

  synthesize(): void {
    const principalId = typeof this.props.principalId === 'string'
      ? this.props.principalId
      : this.props.principalId.principalId;

    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Authorization/roleAssignments',
      apiVersion: '2022-04-01',
      name: this.props.name,
      properties: {
        roleDefinitionId: `subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '${this.props.roleDefinitionId}')`,
        principalId: principalId,
        principalType: '\'ServicePrincipal\'',
      },
      dependsOn: this.explicitDependencies.length > 0 ? this.explicitDependencies : undefined,
    });
  }
}
