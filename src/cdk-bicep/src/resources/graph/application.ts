import { BicepConstruct } from './bicepConstruct';
import * as types from './types';
import { BicepTemplate } from '../../deploy/template';

/**
 * Properties for Graph Application construct
 */
export interface ApplicationProps {
  /** Display name of the application */
  readonly displayName: string;
  /** Redirect URIs for web authentication */
  readonly redirectUris: string[];
  /** Supported account types */
  readonly signInAudience?: types.SignInAudience;
  /** App roles for the application */
  readonly appRoles?: Array<{
    id: string;
    displayName: string;
    description: string;
    value: string;
    allowedMemberTypes: types.AllowedMemberType[];
    isEnabled: boolean;
  }>;
  /** Required resource access permissions */
  readonly requiredResourceAccess?: Array<{
    resourceAppId: types.ResourceAppId;
    resourceAccess: Array<{
      id: types.MicrosoftGraphPermission;
      type: types.PermissionType;
    }>;
  }>;
  /** Identifier URIs (App ID URIs) for the application when used as a resource app */
  readonly identifierUris?: string[];
  /** Optional claims configuration */
  readonly optionalClaims?: {
    idToken?: Array<{
      name: string;
      essential: boolean;
      source?: string;
    }>;
  };
}

/**
 * CDK-style construct for Microsoft Graph Application
 */
export class Application extends BicepConstruct {
  public readonly appId: string;
  public readonly applicationId: string;

  constructor(template: BicepTemplate, resourceName: string, public readonly props: ApplicationProps) {
    super(template, resourceName);
    const pascalName = this.toPascalCase(resourceName);
    this.appId = `${pascalName}.appId`;
    this.applicationId = `${pascalName}.id`;
  }

  synthesize(): void {
    const resource: any = {
      type: 'Microsoft.Graph/applications',
      apiVersion: 'v1.0',
      comment: 'Application registration with OAuth configuration',
      uniqueName: this.props.displayName,
      displayName: this.props.displayName,
      signInAudience: this.props.signInAudience || types.SignInAudience.AZURE_AD_MY_ORG,
      appRoles: this.props.appRoles || [],
      web: {
        redirectUris: this.props.redirectUris,
        implicitGrantSettings: {
          enableIdTokenIssuance: true,
          enableAccessTokenIssuance: false,
        },
      },
      requiredResourceAccess: this.props.requiredResourceAccess || [
        {
          resourceAppId: types.ResourceAppId.MICROSOFT_GRAPH,
          resourceAccess: [
            {
              id: types.MicrosoftGraphPermission.USER_READ,
              type: types.PermissionType.SCOPE,
            },
          ],
        },
      ],
    };

    if (this.props.identifierUris) {
      resource.identifierUris = this.props.identifierUris;
    }

    if (this.props.optionalClaims) {
      resource.optionalClaims = this.props.optionalClaims;
    }

    this.template.addResource(this.resourceName, resource);
  }
}