import * as path from 'path';
import * as core from 'aws-cdk-lib';
import {
  aws_cognito as cognito,
  aws_iam as iam,
  aws_lambda as lambda,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

type AccountTakeoverRiskConfig = cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty;
type CompromisedCredentialsRiskConfig = cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty;

/**
 * Specification for one Cognito app client (e.g. one brand or one front-end).
 * Public SPA clients: no secret, PKCE (authorization-code grant), SRP.
 */
export interface CognitoAppClientSpec {
  /** Logical key used as the construct id and the key in {@link CognitoCustomerPool.userPoolClients}. */
  readonly key: string;
  /** OAuth2 callback URLs for this client (used only by the social/hosted redirect flow). */
  readonly callbackUrls?: string[];
  /** Logout URLs for this client. */
  readonly logoutUrls?: string[];
  /** Identity providers this client supports. @default [COGNITO] */
  readonly supportedIdentityProviders?: cognito.UserPoolClientIdentityProvider[];
  /** Generate a client secret. @default false (public SPA client) */
  readonly generateSecret?: boolean;
}

/**
 * Optional Cognito Identity Pool + ABAC (attributes-for-access-control) config.
 * Maps token claims to principal tags so downstream IAM can scope on them.
 */
export interface CognitoIdentityPoolAbacConfig {
  /** Allow unauthenticated (guest) identities. @default false */
  readonly allowUnauthenticatedIdentities?: boolean;
  /**
   * Claim → principal-tag mapping, e.g. `{ sub: 'customer-id' }`. Applied to the
   * user-pool provider so authenticated sessions carry these as `aws:PrincipalTag/*`.
   */
  readonly principalTags?: Record<string, string>;
  /** Managed policies for the authenticated role. @default none (attach your own). */
  readonly authenticatedRoleManagedPolicies?: iam.IManagedPolicy[];
}

/**
 * Props for {@link CognitoCustomerPool}. Every value is generic — no
 * project/brand/domain specifics are baked in; pass them here.
 */
export interface CognitoCustomerPoolProps {
  /** User pool name. */
  readonly userPoolName?: string;
  /** Cognito hosted-UI domain prefix (globally unique). */
  readonly cognitoDomainPrefix: string;
  /** App clients to create (typically one per brand/front-end). At least one. */
  readonly appClients: CognitoAppClientSpec[];
  /** Enable self-service sign-up. @default false */
  readonly selfSignUpEnabled?: boolean;
  /** MFA enforcement. @default REQUIRED */
  readonly mfa?: cognito.Mfa;
  /** Second factors. @default { otp: true, sms: false } */
  readonly mfaSecondFactor?: cognito.MfaSecondFactor;
  /** Password policy. @default minLength 12, upper/lower/digits/symbols. */
  readonly passwordPolicy?: cognito.PasswordPolicy;
  /** Advanced security mode (threat protection). @default OFF */
  readonly advancedSecurityMode?: cognito.AdvancedSecurityMode;
  /** Standard attributes config. */
  readonly standardAttributes?: cognito.StandardAttributes;
  /** Custom attributes. */
  readonly customAttributes?: { [key: string]: cognito.ICustomAttribute };
  /** Enable the CUSTOM_AUTH flow on app clients. @default false */
  readonly enableCustomAuthFlow?: boolean;
  /** Access token validity. @default 1 hour */
  readonly accessTokenValidity?: core.Duration;
  /** ID token validity. @default 1 hour */
  readonly idTokenValidity?: core.Duration;
  /** Refresh token validity. @default 30 days */
  readonly refreshTokenValidity?: core.Duration;
  /** Cognito groups to create. */
  readonly groups?: string[];
  /**
   * Pre-token-generation Lambda (V2). @default a bundled no-op library Lambda is
   * created. Pass your own to customise emitted claims.
   */
  readonly preTokenGenerationLambda?: lambda.IFunction;
  /**
   * L1 account-takeover risk configuration (requires {@link advancedSecurityMode}
   * ENFORCED/AUDIT). Passed through to CfnUserPoolRiskConfigurationAttachment.
   */
  readonly accountTakeoverRiskConfiguration?: AccountTakeoverRiskConfig;
  /** L1 compromised-credentials risk configuration. */
  readonly compromisedCredentialsRiskConfiguration?: CompromisedCredentialsRiskConfig;
  /** Optional identity pool + ABAC configuration. */
  readonly identityPool?: CognitoIdentityPoolAbacConfig;
  /** Removal policy for the pool. @default RETAIN */
  readonly removalPolicy?: core.RemovalPolicy;
}

/**
 * A generic, reusable secure Cognito **customer** user pool for the custom-UI
 * (client-side SRP) authentication pattern: public PKCE app clients, MFA,
 * strong password policy, optional advanced-security threat protection,
 * per-client (per-brand) app clients, and an optional identity pool with ABAC.
 *
 * Provisions ONLY the identity provider. It knows nothing about CloudFront,
 * sessions, or any specific project — pair it with `CognitoSessionBackend`
 * (session substrate) and `CognitoCustomUiAuth` (edge/CDN).
 */
export class CognitoCustomerPool extends constructs.Construct {
  public readonly userPool: cognito.UserPool;
  /** App clients keyed by {@link CognitoAppClientSpec.key}. */
  public readonly userPoolClients: Record<string, cognito.UserPoolClient>;
  /** The first app client, for convenience. */
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly userPoolDomain: cognito.UserPoolDomain;
  /** Hosted-UI domain URL, e.g. `<prefix>.auth.<region>.amazoncognito.com`. */
  public readonly cognitoDomainUrl: string;
  public readonly identityPool?: cognito.CfnIdentityPool;
  public readonly authenticatedRole?: iam.Role;

  constructor(scope: constructs.Construct, id: string, props: CognitoCustomerPoolProps) {
    super(scope, id);

    if (!props.appClients || props.appClients.length === 0) {
      throw new Error('CognitoCustomerPool requires at least one app client');
    }

    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: props.userPoolName,
      selfSignUpEnabled: props.selfSignUpEnabled ?? false,
      signInAliases: { email: true },
      signInCaseSensitive: false,
      mfa: props.mfa ?? cognito.Mfa.REQUIRED,
      mfaSecondFactor: props.mfaSecondFactor ?? { otp: true, sms: false },
      passwordPolicy: props.passwordPolicy ?? {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      advancedSecurityMode: props.advancedSecurityMode ?? cognito.AdvancedSecurityMode.OFF,
      standardAttributes: props.standardAttributes,
      customAttributes: props.customAttributes,
      autoVerify: { email: true },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: props.removalPolicy ?? core.RemovalPolicy.RETAIN,
    });

    const preTokenLambda = props.preTokenGenerationLambda ?? new lambda.Function(this, 'PreTokenLambda', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/pre-token')),
      timeout: core.Duration.seconds(5),
    });
    this.userPool.addTrigger(cognito.UserPoolOperation.PRE_TOKEN_GENERATION_CONFIG, preTokenLambda, cognito.LambdaVersion.V2_0);

    if (props.groups) {
      for (const group of props.groups) {
        new cognito.CfnUserPoolGroup(this, `Group${group}`, {
          userPoolId: this.userPool.userPoolId,
          groupName: group,
        });
      }
    }

    // Optional advanced-security risk configuration (L1).
    if (props.accountTakeoverRiskConfiguration || props.compromisedCredentialsRiskConfiguration) {
      new cognito.CfnUserPoolRiskConfigurationAttachment(this, 'RiskConfig', {
        userPoolId: this.userPool.userPoolId,
        clientId: 'ALL',
        accountTakeoverRiskConfiguration: props.accountTakeoverRiskConfiguration,
        compromisedCredentialsRiskConfiguration: props.compromisedCredentialsRiskConfiguration,
      });
    }

    this.userPoolClients = {};
    for (const spec of props.appClients) {
      const client = new cognito.UserPoolClient(this, `Client${spec.key}`, {
        userPool: this.userPool,
        generateSecret: spec.generateSecret ?? false,
        authFlows: {
          userSrp: true,
          custom: props.enableCustomAuthFlow ?? false,
          // userPassword / adminUserPassword intentionally omitted (disabled).
        },
        oAuth: {
          flows: { authorizationCodeGrant: true },
          scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
          callbackUrls: spec.callbackUrls,
          logoutUrls: spec.logoutUrls,
        },
        supportedIdentityProviders: spec.supportedIdentityProviders ?? [cognito.UserPoolClientIdentityProvider.COGNITO],
        preventUserExistenceErrors: true,
        enableTokenRevocation: true,
        accessTokenValidity: props.accessTokenValidity ?? core.Duration.hours(1),
        idTokenValidity: props.idTokenValidity ?? core.Duration.hours(1),
        refreshTokenValidity: props.refreshTokenValidity ?? core.Duration.days(30),
      });
      this.userPoolClients[spec.key] = client;
    }
    this.userPoolClient = this.userPoolClients[props.appClients[0].key];

    this.userPoolDomain = this.userPool.addDomain('CognitoDomain', {
      cognitoDomain: { domainPrefix: props.cognitoDomainPrefix },
    });
    this.cognitoDomainUrl = `${props.cognitoDomainPrefix}.auth.${core.Stack.of(this).region}.amazoncognito.com`;

    if (props.identityPool) {
      const idp = props.identityPool;
      this.identityPool = new cognito.CfnIdentityPool(this, 'IdentityPool', {
        allowUnauthenticatedIdentities: idp.allowUnauthenticatedIdentities ?? false,
        cognitoIdentityProviders: props.appClients.map(spec => ({
          clientId: this.userPoolClients[spec.key].userPoolClientId,
          providerName: this.userPool.userPoolProviderName,
          serverSideTokenCheck: true,
        })),
      });

      this.authenticatedRole = new iam.Role(this, 'AuthenticatedRole', {
        assumedBy: new iam.FederatedPrincipal(
          'cognito-identity.amazonaws.com',
          {
            'StringEquals': { 'cognito-identity.amazonaws.com:aud': this.identityPool.ref },
            'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': 'authenticated' },
          },
          'sts:AssumeRoleWithWebIdentity',
        ),
        managedPolicies: idp.authenticatedRoleManagedPolicies,
      });

      new cognito.CfnIdentityPoolRoleAttachment(this, 'IdentityPoolRoles', {
        identityPoolId: this.identityPool.ref,
        roles: { authenticated: this.authenticatedRole.roleArn },
      });

      // ABAC: map claims to principal tags on the user-pool provider.
      if (idp.principalTags && Object.keys(idp.principalTags).length > 0) {
        new cognito.CfnIdentityPoolPrincipalTag(this, 'PrincipalTags', {
          identityPoolId: this.identityPool.ref,
          identityProviderName: this.userPool.userPoolProviderName,
          useDefaults: false,
          principalTags: idp.principalTags,
        });
      }
    }
  }
}
