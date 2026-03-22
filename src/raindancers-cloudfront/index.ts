export { AuthInfrastructure, AuthInfrastructureProps, AppSpec } from './patterns/auth-infrastructure';
export { SsmCrossRegionWriter, SsmCrossRegionWriterProps } from './ssm-cross-region-writer';
export * as cloudfront from './cloudfront';
export { Extension, ExtensionConfig, SecuredCloudFront, RoleMatchMode } from './cloudfront/patterns/securedCloudFront';
export { CognitoSecuredCloudFront, CognitoCloudFrontProps } from './cloudfront/patterns/cognito-secured-cloudfront';
export { ViteFrontendDeployment, ViteFrontendDeploymentProps } from './deployment/viteFrontendDeployment';
