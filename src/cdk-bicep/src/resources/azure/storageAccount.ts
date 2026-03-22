import { BicepTemplate } from '../../deploy/template';
import { BicepConstruct } from '../graph/bicepConstruct';

export interface StorageAccountProps {
  readonly name: string;
}

export class StorageAccount extends BicepConstruct {
  public readonly name: string;

  constructor(template: BicepTemplate, resourceName: string, private props: StorageAccountProps) {
    super(template, resourceName);
    const pascalName = this.toPascalCase(resourceName);
    this.name = `${pascalName}.name`;
  }

  synthesize(): void {
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Storage/storageAccounts',
      apiVersion: '2023-01-01',
      name: this.props.name,
      location: 'location',
      sku: { name: 'Standard_LRS' },
      kind: 'StorageV2',
      properties: {
        minimumTlsVersion: 'TLS1_2',
        supportsHttpsTrafficOnly: true,
      },
    });
  }
}
