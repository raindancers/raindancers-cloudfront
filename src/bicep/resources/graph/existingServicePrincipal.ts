import { BicepConstruct } from './bicepConstruct';
import { BicepTemplate } from '../../deploy/template';

/**
 * Properties for existing Service Principal lookup
 */
export interface ExistingServicePrincipalProps {
  /** The application (client) ID of the service principal to look up */
  readonly appId: string;
}

/**
 * CDK-style construct for looking up an existing Microsoft Graph Service Principal
 * Uses Bicep 'existing' keyword to reference service principals by appId
 */
export class ExistingServicePrincipal extends BicepConstruct {
  public readonly servicePrincipalId: string;

  constructor(template: BicepTemplate, resourceName: string, public readonly props: ExistingServicePrincipalProps) {
    super(template, resourceName);
    this.servicePrincipalId = `${this.toPascalCase(resourceName)}.id`;
  }

  synthesize(): void {
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Graph/servicePrincipals',
      apiVersion: 'v1.0',
      existing: true,
      comment: 'Reference to existing service principal',
      appId: this.props.appId,
    });
  }
}
