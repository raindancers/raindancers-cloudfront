import { Application } from './application';
import { BicepConstruct } from './bicepConstruct';
import { BicepTemplate } from '../../deploy/template';

/**
 * Properties for Graph Service Principal construct
 */
export interface ServicePrincipalProps {
  /** The application to create a service principal for */
  readonly application: Application;
  /** Whether user assignment is required for this app */
  readonly appRoleAssignmentRequired?: boolean;
}

/**
 * CDK-style construct for Microsoft Graph Service Principal (Enterprise Application)
 * This represents the Enterprise Application instance in your tenant
 */
export class ServicePrincipal extends BicepConstruct {
  public readonly servicePrincipalId: string;

  constructor(template: BicepTemplate, resourceName: string, public readonly props: ServicePrincipalProps) {
    super(template, resourceName);
    this.servicePrincipalId = `${this.toPascalCase(resourceName)}.id`;
  }

  synthesize(): void {
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Graph/servicePrincipals',
      apiVersion: 'v1.0',
      comment: 'Enterprise application instance',
      appId: this.props.application.appId,
      appRoleAssignmentRequired: this.props.appRoleAssignmentRequired ?? true,
      dependsOn: this.explicitDependencies.length > 0 ? this.explicitDependencies : undefined,
    });
  }
}