import { BicepTemplate } from '../../deploy/template';
import { BicepConstruct } from '../graph/bicepConstruct';

export interface AppServicePlanProps {
  readonly name: string;
}

export class AppServicePlan extends BicepConstruct {
  public readonly id: string;

  constructor(template: BicepTemplate, resourceName: string, private props: AppServicePlanProps) {
    super(template, resourceName);
    const pascalName = this.toPascalCase(resourceName);
    this.id = `${pascalName}.id`;
  }

  synthesize(): void {
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Web/serverfarms',
      apiVersion: '2022-09-01',
      name: this.props.name,
      location: 'location',
      sku: { name: 'Y1', tier: 'Dynamic' },
      properties: { reserved: true },
    });
  }
}
