# Security Architecture Principles

These are non-negotiable security principles that MUST be followed in all solutions.

## Principle 1: Authorization Must Not Be Performed in Application Code

**Rule:** Lambda functions (or any application code) MUST NEVER make authorization decisions.

**Rationale:**
- Application code can be compromised through vulnerabilities
- A compromised Lambda could bypass authorization checks
- Authorization logic in code is harder to audit and verify
- Changes to authorization require code deployments

**Enforcement:**
- Authorization MUST be enforced by AWS IAM policies (identity-based or resource-based)
- Lambda functions MUST only handle business logic after IAM has authorized the request
- Session tags, resource policies, and IAM conditions are the ONLY acceptable authorization mechanisms

**Examples:**

❌ **WRONG - Authorization in Lambda:**
```python
def lambda_handler(event, context):
    # Parse JWT to check roles
    if 'Animals' not in jwt_roles:
        return {'statusCode': 403}
    
    # Access DynamoDB
    dynamodb.scan(TableName='Animals')
```

✅ **CORRECT - Authorization via IAM:**
```python
def lambda_handler(event, context):
    # IAM already authorized via session tags + resource policy
    # Lambda just performs business logic
    dynamodb.scan(TableName='Animals')
```

## Principle 2: Prefer Resource-Based Policies Over Identity-Based Policies

**Rule:** For same-account access, use resource-based policies on resources (DynamoDB, S3, etc.) instead of identity-based policies on roles.

**Rationale:**
- Resource-based policies are more explicit about what can access the resource
- Easier to audit resource access by looking at the resource policy
- Follows principle of least privilege at the resource level
- More flexible for future cross-account scenarios
- Clearer separation of concerns (resource owner controls access)

**Enforcement:**
- DynamoDB tables MUST use resource-based policies with session tag conditions
- Identity-based policies should only be used when resource-based policies are not available
- For cross-account access, use BOTH identity-based AND resource-based policies

**Examples:**

❌ **WRONG - Identity-based policy on role:**
```typescript
webIdentityRole.addToPolicy(new iam.PolicyStatement({
  actions: ['dynamodb:Scan'],
  resources: [animalsTable.tableArn],
  conditions: {
    'StringEquals': {
      'aws:PrincipalTag/Animals': 'true'
    }
  }
}));
```

✅ **CORRECT - Resource-based policy on table:**
```typescript
animalsTable.addToResourcePolicy(new iam.PolicyStatement({
  principals: [new iam.ArnPrincipal(webIdentityRole.roleArn)],
  actions: ['dynamodb:Scan'],
  resources: [animalsTable.tableArn],
  conditions: {
    'StringEquals': {
      'aws:PrincipalTag/Animals': 'true'
    }
  }
}));
```

## Principle 3: Accept Complexity When Security Requires It

**Rule:** When proper security architecture requires complex implementation, accept the complexity. Do not suggest simpler alternatives that violate security principles.

**Rationale:**
- Security is not negotiable
- Convenience should never trump security
- Complex security infrastructure is maintainable and auditable
- Shortcuts create technical debt and security vulnerabilities

**Enforcement:**
- When user states security requirements, do not suggest workarounds
- If implementation is complex, break it into manageable steps
- Document the complexity and provide clear implementation plans
- Never suggest "easier" alternatives that compromise security

**Examples:**

❌ **WRONG - Suggesting workaround:**
```
"Custom Claims Provider is complex. Why not just parse the JWT in Lambda 
and make authorization decisions there? It's much simpler."
```

✅ **CORRECT - Accept complexity:**
```
"Custom Claims Provider requires Azure Function infrastructure, but it's 
the only way to emit claims in AWS session tag format while maintaining 
authorization at the IAM layer. Here's the implementation plan..."
```

## When Suggesting Solutions

Before suggesting ANY solution, verify it meets ALL three principles:

1. ✅ Does authorization happen in IAM policies (not application code)?
2. ✅ Does it use resource-based policies (when available)?
3. ✅ Does it maintain security even if more complex?

If the answer to any question is NO, do not suggest the solution.

## Exceptions

There are NO exceptions to these principles. If a solution violates these principles, it is not acceptable regardless of:
- Implementation complexity
- Development time
- Convenience
- Cost
- Existing patterns in other projects

Security architecture principles are non-negotiable.
