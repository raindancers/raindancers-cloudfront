# Bicep Template Validation Rule

## Rule: Always Validate Bicep Before Deployment

When modifying code that affects Bicep template generation, you MUST:

1. **Synthesize the template**
   ```bash
   npx cdk synth
   ```

2. **Check Bicep linting**
   ```bash
   az bicep build --file cdk.out/bicep/cdk-Deployment.bicep
   ```

3. **Review linter warnings and errors**
   - Fix all errors before deployment
   - Address warnings that indicate real issues
   - Document any intentionally ignored warnings

4. **Only then proceed with deployment**

## When This Rule Applies

Apply this rule when modifying:
- Bicep construct classes (`src/constructs/bicep/resources/`)
- Bicep pattern classes (`src/constructs/bicep/patterns/`)
- Bicep template builder (`src/constructs/bicep/deploy/template.ts`)
- Any code that calls `template.addResource()` or `template.synthesize()`

## Why This Rule Exists

Bicep deployment failures in CloudFormation are expensive:
- Failed deployments trigger rollbacks (time-consuming)
- Debugging requires checking Lambda logs and CloudFormation events
- Stack can get stuck in UPDATE_ROLLBACK_FAILED state
- Each deployment cycle takes 5-10 minutes

Catching errors during synthesis takes seconds.

## Common Bicep Linting Errors to Watch For

- **BCP173**: Property cannot be used in existing resource declaration (e.g., `location` on existing resources)
- **BCP057**: Name does not exist in current context (resource name typos, case sensitivity)
- **no-unused-existing-resources**: Existing resource declared but never used
- **BCP018**: Expected token errors (usually CDK tokens like `${Token[AWS.AccountId.X]}`, **cannot be suppressed** as it's a syntax error, but deployment works because Lambda replaces tokens before deploying)

## Workflow

```
Code Change → Synth → Lint → Fix Errors → Synth Again → Lint Clean → Deploy
```

Never skip the synth + lint steps before deployment.
