import { BicepTemplate } from '../../deploy/template';
import { BicepConstruct } from '../graph/bicepConstruct';

export interface ManagedIdentityProps {
  readonly name: string;
}

export class ManagedIdentity extends BicepConstruct {
  public readonly id: string;
  public readonly principalId: string;
  public readonly clientId: string;

  constructor(template: BicepTemplate, resourceName: string, private props: ManagedIdentityProps) {
    super(template, resourceName);
    const pascalName = this.toPascalCase(resourceName);
    this.id = `${pascalName}.id`;
    this.principalId = `${pascalName}.properties.principalId`;
    this.clientId = `${pascalName}.properties.clientId`;
  }

  synthesize(): void {
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.ManagedIdentity/userAssignedIdentities',
      apiVersion: '2023-01-31',
      name: this.props.name,
      location: 'location',
    });
  }
}
