# Local Debugging: wire-custom-claims-extension.sh

## How the script runs in deployment vs locally

### Deployment mode (default)
In deployment, this script runs inside an Azure `DeploymentScript` resource, executed by a managed identity that has been granted the required Graph application permissions. The managed identity authenticates via the Azure CLI (`az account get-access-token`), which works automatically in that container environment.

### Local mode
Locally, the `az` CLI uses your personal delegated token, which does **not** have the Graph application permissions (`CustomAuthenticationExtension.ReadWrite.All`, `EventListener.ReadWrite.All`, `Policy.ReadWrite.ApplicationConfiguration`, `Policy.Read.All`, `Application.ReadWrite.All`) needed by this script. You must use a service principal with those permissions granted via `client_credentials` instead.

## Running locally

### Step 1: Create a test service principal

Run the setup script once to create an app registration with the required Graph application permissions:

```bash
bash scripts/setup-test-sp.sh
```

This outputs `TEST_TENANT_ID`, `TEST_CLIENT_ID`, and `TEST_CLIENT_SECRET`. Export them:

```bash
export TEST_TENANT_ID=<value>
export TEST_CLIENT_ID=<value>
export TEST_CLIENT_SECRET=<value>
```

### Step 2: Set the script's required environment variables

These are the same env vars the `DeploymentScript` injects at deployment time. Get the values from the deployed Azure resources:

```bash
export FUNCTION_HOSTNAME="<function-app-hostname>"   # e.g. clf-claims-func-6qx5xi3p.azurewebsites.net
export FUNCTION_APP_ID="<function-app-registration-appId>"
export CLF_APP_ID="<clf-app-registration-appId>"
export EXT_DISPLAY_NAME="<namePrefix>-claims-provider"  # e.g. clf-claims-provider
```

### Step 3: Run the script

```bash
bash src/constructsForPackaging/cdk-bicep/src/patterns/scripts/wire-custom-claims-extension.sh
```

When `TEST_CLIENT_ID` is set, the script automatically uses `client_credentials` to obtain a token. When it is not set (deployment), it uses `az account get-access-token`.

### Step 4: Clean up the test service principal

```bash
az ad app delete --id $TEST_CLIENT_ID
```

## Why we use curl instead of az rest

Microsoft's recommended pattern for calling Graph API from Azure CLI DeploymentScripts is `az rest`, which handles authentication automatically using the managed identity context. However, this script uses raw `curl` with manual token management for a specific reason: the permission propagation retry loop.

The retry loop acquires a token, decodes the JWT payload, and inspects the `roles` claim to verify all required Graph permissions have propagated before proceeding. `az rest` acquires its own token internally and doesn't expose it, making JWT inspection impossible. Manual token management via `az account get-access-token` is therefore required to support this retry logic.

If the propagation retry is ever removed, the script should be refactored to use `az rest`.

## Why delegated az CLI tokens don't work

The `az` CLI authenticates as the Microsoft Azure CLI app registration, which has not been granted the required Graph **application** permissions in your tenant. You will see errors like `"The application does not have any of the required delegated permissions"`. The test SP uses `client_credentials` which grants application permissions — exactly replicating what the managed identity does in deployment.

## Known issue: `set -x` causes deployment failures

Do **not** add `set -x` to this script for deployment debugging. The script acquires a Graph JWT (~2KB) and `set -x` prints every command with its full arguments, including `TOKEN=<full JWT>` and `Authorization: Bearer <full JWT>` on every curl call. With 6 retry iterations this easily exceeds Azure's 256KB aggregated error message limit, causing the deployment to fail with:

```
The aggregated deployment error is too large. Please list deployment operations to get the deployment details.
```

To debug deployment failures, use `az deployment-scripts show-log` after the script runs, or add targeted `echo` statements instead of `set -x`.

## Known issue: permission propagation race condition

The managed identity's Graph app role assignments (`Policy.Read.All`, `Policy.ReadWrite.ApplicationConfiguration`, `Application.ReadWrite.All`, etc.) are created in the same Bicep deployment as the DeploymentScript. Entra may not have propagated these permissions by the time the script runs, causing the token to be missing required roles.

The script handles this with a retry loop at startup: it acquires a token, decodes the JWT, checks all required roles are present, and retries up to 6 times with 20s gaps (120s total) before failing. You will see output like:

```
Waiting for role propagation (attempt 1/6), missing: Policy.Read.All Policy.ReadWrite.ApplicationConfiguration
```

This is expected on fresh deployments. If it fails after 120s, check the managed identity's app role assignments in Entra.
