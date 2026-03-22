import { BicepConstruct } from './bicepConstruct';
import { ExistingServicePrincipal } from './existingServicePrincipal';
import { Group } from './group';
import { ServicePrincipal } from './servicePrincipal';
import { BicepTemplate } from '../../deploy/template';

/**
 * Properties for Graph App Role Assignment construct
 */
export interface AppRoleAssignmentProps {
  /** The service principal (resource) that owns the app role */
  readonly resourceServicePrincipal: ServicePrincipal | ExistingServicePrincipal | string;
  /** The principal (group, user, or managed identity) to assign the role to */
  readonly principal: Group | string;
  /** The app role ID (use '00000000-0000-0000-0000-000000000000' for default access) */
  readonly appRoleId: string;
}

/**
 * CDK-style construct for Microsoft Graph App Role Assignment
 * Assigns a principal (group, user, managed identity) to a service principal app role
 */
export class AppRoleAssignment extends BicepConstruct {
  constructor(template: BicepTemplate, resourceName: string, public readonly props: AppRoleAssignmentProps) {
    super(template, resourceName);
  }

  synthesize(): void {
    const principalId = typeof this.props.principal === 'string'
      ? this.props.principal
      : this.props.principal.groupId;

    const resourceId = typeof this.props.resourceServicePrincipal === 'string'
      ? this.props.resourceServicePrincipal
      : this.props.resourceServicePrincipal.servicePrincipalId;

    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Graph/appRoleAssignedTo',
      apiVersion: 'v1.0',
      comment: 'Assign principal to application role',
      principalId: principalId,
      resourceId: resourceId,
      appRoleId: this.props.appRoleId,
      dependsOn: this.explicitDependencies.length > 0 ? this.explicitDependencies : undefined,
    });
  }
}