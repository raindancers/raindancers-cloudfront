import * as core from 'aws-cdk-lib';
import {
  aws_iam as iam,
} from 'aws-cdk-lib';
import * as constructs from 'constructs';

export interface OAuthEdgeRoleProps {
  readonly roleName: string;
}

export class OAuthEdgeRole extends constructs.Construct {
  public readonly role: iam.Role;

  constructor(scope: constructs.Construct, id: string, props: OAuthEdgeRoleProps) {
    super(scope, id);

    this.role = new iam.Role(this, 'Role', {
      roleName: props.roleName,
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    this.role.addToPolicy(new iam.PolicyStatement({
      actions: ['sts:GetWebIdentityToken'],
      resources: ['*'],
    }));
  }
}
