import { BicepTemplate } from '../../deploy/template';
import { BicepConstruct } from '../graph/bicepConstruct';

export interface LogAnalyticsWorkspaceProps {
  readonly name: string;
}

export class LogAnalyticsWorkspace extends BicepConstruct {
  public readonly id: string;

  constructor(template: BicepTemplate, resourceName: string, private props: LogAnalyticsWorkspaceProps) {
    super(template, resourceName);
    const pascalName = this.toPascalCase(resourceName);
    this.id = `${pascalName}.id`;
  }

  synthesize(): void {
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.OperationalInsights/workspaces',
      apiVersion: '2022-10-01',
      name: this.props.name,
      location: 'location',
      properties: {
        sku: { name: 'PerGB2018' },
        retentionInDays: 30,
      },
    });
  }
}
