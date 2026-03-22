import { BicepConstruct } from './bicepConstruct';
import { BicepTemplate } from '../../deploy/template';

/**
 * Properties for Azure AD Group
 */
export interface GroupProps {
  /** Display name of the group */
  readonly displayName: string;
  /** Description of the group */
  readonly description?: string;
  /** Group types (e.g., ['Unified'] for Microsoft 365 groups) */
  readonly groupTypes?: string[];
  /** Whether the group is mail-enabled */
  readonly mailEnabled?: boolean;
  /** Whether the group is security-enabled */
  readonly securityEnabled?: boolean;
}

/**
 * CDK-style construct for Azure AD Group
 */
export class Group extends BicepConstruct {
  public readonly groupId: string;

  constructor(template: BicepTemplate, resourceName: string, private props: GroupProps) {
    super(template, resourceName);
    this.groupId = `${this.toPascalCase(resourceName)}.id`;
  }

  synthesize(): void {
    const mailNickname = this.props.displayName.toLowerCase().replace(/[^a-z0-9]/g, '');
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Graph/groups',
      apiVersion: 'v1.0',
      comment: `Security group: ${this.props.displayName}`,
      uniqueName: this.props.displayName,
      displayName: this.props.displayName,
      description: this.props.description,
      groupTypes: this.props.groupTypes || [],
      mailEnabled: this.props.mailEnabled || false,
      securityEnabled: this.props.securityEnabled !== false,
      mailNickname: mailNickname,
    });
  }
}