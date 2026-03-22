/**
 * Microsoft Graph resource app IDs and permission constants
 */

export enum ResourceAppId {
  MICROSOFT_GRAPH = '00000003-0000-0000-c000-000000000000',
}

export enum MicrosoftGraphPermission {
  // User permissions (Delegated)
  USER_READ = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d',
  USER_READ_WRITE = 'b4e74841-8e56-480b-be8b-910348b18b4c',
  USER_READ_ALL = 'a154be20-db9c-4678-8ab7-66f6cc099a59',
  USER_READ_WRITE_ALL = '204e0828-b5ca-4ad8-b9f3-f32a958e7cc4',

  // Directory permissions (Delegated)
  DIRECTORY_READ_ALL = '06da0dbc-49e2-44d2-8312-53f166ab848a',
  DIRECTORY_READ_WRITE_ALL = 'c5366453-9fb0-48a5-a156-24f0c49a4b84',

  // Group permissions (Delegated)
  GROUP_READ_ALL = '5f8c59db-677d-491f-a6b8-5f174b11ec1d',
  GROUP_READ_WRITE_ALL = '4e46008b-f24c-477d-8fff-7bb4ec7aafe0',

  // Application permissions (Application)
  USER_READ_ALL_APP = 'df021288-bdef-4463-88db-98f22de89214',
  USER_READ_WRITE_ALL_APP = '741f803b-c850-494e-b5df-cde7c675a1ca',
  DIRECTORY_READ_ALL_APP = '7ab1d382-f21e-4acd-a863-ba3e13f7da61',
  DIRECTORY_READ_WRITE_ALL_APP = '19dbc75e-c2e2-444c-a770-ec69d8559fc7',
  GROUP_READ_ALL_APP = '5b567255-7703-4780-807c-7be8301ae99b',
  GROUP_READ_WRITE_ALL_APP = '62a82d76-70ea-41e2-9197-370581804d09',

  // Custom Authentication Extension permissions (Application)
  CUSTOM_AUTH_EXT_RECEIVE_PAYLOAD = '214e810f-fda8-4fd7-a475-29461495eb00',

  // Application permissions (Application)
  APPLICATION_READ_WRITE_ALL = '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9',

  // Policy permissions (Application)
  POLICY_READ_ALL = '246dd0d5-5bd0-4def-940b-0421030a5b68',
  POLICY_READ_WRITE_APPLICATION_CONFIGURATION = 'be74164b-cff1-491c-8741-e671cb536e13',

  // Mail permissions (Delegated)
  MAIL_READ = '570282fd-fa5c-430d-a7fd-fc8dc98a9dca',
  MAIL_READ_WRITE = '024d486e-b451-40bb-833d-3e66d98c5c73',
  MAIL_SEND = 'e383f46e-2787-4529-855e-0e479a3ffac0',

  // Calendar permissions (Delegated)
  CALENDARS_READ = '465a38f9-76ea-45b9-9f34-9e8b0d4b0b42',
  CALENDARS_READ_WRITE = '1ec239c2-d7c9-4623-a91a-a9775856bb36',

  // Files permissions (Delegated)
  FILES_READ = '10465720-29dd-4523-a11a-6a75c743c9d9',
  FILES_READ_WRITE = '5c28f0bf-8a70-41f1-8ab2-9032436ddb65',
  FILES_READ_ALL = 'df85f4d6-205c-4ac5-a5ea-6bf408dba283',
  FILES_READ_WRITE_ALL = '863451e7-0667-486c-a5d6-d135439485f0',
}

export enum PermissionType {
  SCOPE = 'Scope',
  ROLE = 'Role',
}

export enum SignInAudience {
  AZURE_AD_MY_ORG = 'AzureADMyOrg',
  AZURE_AD_MULTIPLE_ORGS = 'AzureADMultipleOrgs',
  AZURE_AD_AND_PERSONAL_MICROSOFT_ACCOUNT = 'AzureADandPersonalMicrosoftAccount',
  PERSONAL_MICROSOFT_ACCOUNT = 'PersonalMicrosoftAccount',
}

/**
 * Azure AD App Role allowed member types
 */
export enum AllowedMemberType {
  /** Individual users can be assigned this role */
  USER = 'User',
  /** Service principals/applications can be assigned this role */
  APPLICATION = 'Application',
}
