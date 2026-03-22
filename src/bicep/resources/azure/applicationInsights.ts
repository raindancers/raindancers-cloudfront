import { LogAnalyticsWorkspace } from './logAnalyticsWorkspace';
import { BicepTemplate } from '../../deploy/template';
import { BicepConstruct } from '../graph/bicepConstruct';

export interface ApplicationInsightsProps {
  readonly name: string;
  readonly logAnalyticsWorkspace: LogAnalyticsWorkspace;
}

export class ApplicationInsights extends BicepConstruct {
  public readonly connectionString: string;

  constructor(template: BicepTemplate, resourceName: string, private props: ApplicationInsightsProps) {
    super(template, resourceName);
    const pascalName = this.toPascalCase(resourceName);
    this.connectionString = `${pascalName}.properties.ConnectionString`;
  }

  synthesize(): void {
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Insights/components',
      apiVersion: '2020-02-02',
      name: this.props.name,
      location: 'location',
      kind: 'web',
      properties: {
        Application_Type: 'web',
        WorkspaceResourceId: `${this.props.logAnalyticsWorkspace.id}`,
      },
    });
  }
}
