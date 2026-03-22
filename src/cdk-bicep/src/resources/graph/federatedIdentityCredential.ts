import { Application } from './application';
import { BicepConstruct } from './bicepConstruct';
import { BicepTemplate } from '../../deploy/template';

/**
 * Properties for Federated Identity Credential
 */
export interface FederatedIdentityCredentialProps {
  /** Application to add credential to */
  readonly application: Application;
  /** Name of the credential */
  readonly name: string;
  /** OIDC issuer URL */
  readonly issuer: string;
  /** Subject claim value */
  readonly subject: string;
  /** Audience values */
  readonly audiences: string[];
  /** Description of the credential */
  readonly description?: string;
}

/**
 * CDK-style construct for Federated Identity Credential
 */
export class FederatedIdentityCredential extends BicepConstruct {
  public readonly credentialId: string;

  constructor(template: BicepTemplate, resourceName: string, private props: FederatedIdentityCredentialProps) {
    super(template, resourceName);
    this.credentialId = `${this.toPascalCase(resourceName)}.id`;
  }

  synthesize(): void {
    const appResourceName = this.toPascalCase(this.props.application.getResourceName());
    this.template.addResource(this.resourceName, {
      type: 'Microsoft.Graph/applications/federatedIdentityCredentials',
      apiVersion: 'v1.0',
      comment: 'Federated credential for external identity provider. Note: BCP018 linter error on subject field is expected due to CDK token syntax.',
      linterSuppressions: ['BCP018'],
      name: `${appResourceName}.uniqueName/${this.props.name}`,
      issuer: this.props.issuer,
      subject: this.props.subject,
      description: this.props.description || 'Federated credential for AWS',
      audiences: this.props.audiences,
      dependsOn: this.explicitDependencies.length > 0 ? this.explicitDependencies : undefined,
    });
  }
}