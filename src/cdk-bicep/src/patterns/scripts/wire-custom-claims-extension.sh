#!/bin/bash

echo "START: wire-custom-claims-extension"
REQUIRED_ROLES="Policy.Read.All Policy.ReadWrite.ApplicationConfiguration CustomAuthenticationExtension.ReadWrite.All EventListener.ReadWrite.All"
echo "Acquiring token (attempt 1/6)"
for i in 1 2 3 4 5 6; do
  if [ -n "$TEST_CLIENT_ID" ]; then
    TOKEN=$(curl -s -X POST \
      "https://login.microsoftonline.com/${TEST_TENANT_ID}/oauth2/v2.0/token" \
      -d "grant_type=client_credentials&client_id=${TEST_CLIENT_ID}&client_secret=${TEST_CLIENT_SECRET}&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default" \
      | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
  else
    TOKEN=$(curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com&bypass_cache=true" \
      -H "Metadata: true" \
      | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
  fi
  ROLES=$(echo "$TOKEN" | python3 -c 'import sys,base64,json; t=sys.stdin.read().strip(); p=t.split(".")[1]; p+="=="*((4-len(p)%4)%4); print(" ".join(json.loads(base64.b64decode(p)).get("roles",[])))')
  MISSING=""
  for role in $REQUIRED_ROLES; do
    echo "$ROLES" | grep -q "$role" || MISSING="$MISSING $role"
  done
  [ -z "$MISSING" ] && break
  echo "Waiting for role propagation (attempt $i/6), missing:$MISSING"
  sleep 20
done
if [ -n "$MISSING" ]; then
  echo "Required roles not propagated after 120s:$MISSING"
  exit 1
fi
echo "TOKEN_LEN=${#TOKEN}"
GRAPH="https://graph.microsoft.com/v1.0"
TARGET_URL="https://${FUNCTION_HOSTNAME}/api/CustomClaimsProvider"
RESOURCE_ID="api://${FUNCTION_HOSTNAME}/${FUNCTION_APP_ID}"

echo "STEP: PATCH identifierUris"
curl -s --fail-with-body -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"identifierUris\":[\"$RESOURCE_ID\"]}" \
  "$GRAPH/applications(appId='${FUNCTION_APP_ID}')"

echo "STEP: PATCH acceptMappedClaims"
curl -s --fail-with-body -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"api":{"acceptMappedClaims":true}}' \
  "$GRAPH/applications(appId='${CLF_APP_ID}')"

echo "STEP: check/create service principal"
EXISTING_SP=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$GRAPH/servicePrincipals?\$filter=appId+eq+'${FUNCTION_APP_ID}'" \
  | python3 -c 'import sys,json; v=json.load(sys.stdin)["value"]; print(v[0]["id"] if v else "")')
if [ -z "$EXISTING_SP" ]; then
  curl -s --fail-with-body -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"appId\":\"${FUNCTION_APP_ID}\"}" \
    "$GRAPH/servicePrincipals"
fi

echo "STEP: check/create custom auth extension"
EXISTING_EXT=$(curl -s --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$GRAPH/identity/customAuthenticationExtensions" \
  | python3 -c 'import sys,json,os; exts=[x["id"] for x in json.load(sys.stdin)["value"] if x["displayName"]==os.environ["EXT_DISPLAY_NAME"]]; print(exts[0] if exts else "")')
if [ -z "$EXISTING_EXT" ]; then
  EXTENSION_ID=$(curl -s --fail-with-body -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"@odata.type\":\"#microsoft.graph.onTokenIssuanceStartCustomExtension\",\"displayName\":\"${EXT_DISPLAY_NAME}\",\"description\":\"Custom claims provider for AWS session tags\",\"authenticationConfiguration\":{\"@odata.type\":\"#microsoft.graph.azureAdTokenAuthentication\",\"resourceId\":\"$RESOURCE_ID\"},\"endpointConfiguration\":{\"@odata.type\":\"#microsoft.graph.httpRequestEndpoint\",\"targetUrl\":\"$TARGET_URL\"},\"claimsForTokenConfiguration\":[{\"claimIdInApiResponse\":\"Roles\"}]}" \
    "$GRAPH/identity/customAuthenticationExtensions" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
else
  EXTENSION_ID=$EXISTING_EXT
  curl -s --fail-with-body -X PATCH \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"@odata.type":"#microsoft.graph.onTokenIssuanceStartCustomExtension","claimsForTokenConfiguration":[{"claimIdInApiResponse":"Roles"}]}' \
    "$GRAPH/identity/customAuthenticationExtensions/$EXTENSION_ID"
fi

echo "STEP: check/create claims mapping policy"
POLICY_ID=$(curl -s --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$GRAPH/policies/claimsMappingPolicies" \
  | python3 -c 'import sys,json,os; policies=[x["id"] for x in json.load(sys.stdin)["value"] if x["displayName"]==os.environ["EXT_DISPLAY_NAME"]+"-claims-policy"]; print(policies[0] if policies else "")')
if [ -z "$POLICY_ID" ]; then
  POLICY_BODY='{"ClaimsMappingPolicy":{"Version":1,"IncludeBasicClaimSet":"true","ClaimsSchema":[{"Source":"CustomClaimsProvider","ID":"Roles","JwtClaimType":"https://aws.amazon.com/tags/principal_tags/Roles"}]}}'
  POLICY_DEF=$(echo "$POLICY_BODY" | python3 -c "import json,sys; print(json.dumps(json.dumps(json.loads(sys.stdin.read()))))")
  POLICY_ID=$(curl -s --fail-with-body -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"definition\":[$POLICY_DEF],\"displayName\":\"${EXT_DISPLAY_NAME}-claims-policy\",\"isOrganizationDefault\":false}" \
    "$GRAPH/policies/claimsMappingPolicies" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
fi

echo "STEP: check/assign claims mapping policy"
CLF_SP_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$GRAPH/servicePrincipals(appId='${CLF_APP_ID}')" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
EXISTING_POLICY_ASSIGN=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$GRAPH/servicePrincipals/${CLF_SP_ID}/claimsMappingPolicies" \
  | python3 -c 'import sys,json; policies=[x["id"] for x in json.load(sys.stdin)["value"] if x["id"]==sys.argv[1]]; print(policies[0] if policies else "")' "$POLICY_ID")
if [ -z "$EXISTING_POLICY_ASSIGN" ]; then
  curl -s --fail-with-body -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/$POLICY_ID\"}" \
    "$GRAPH/servicePrincipals/${CLF_SP_ID}/claimsMappingPolicies/\$ref"
fi

echo "STEP: check/create token issuance listener"
EXISTING_LISTENER=$(curl -s --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$GRAPH/identity/authenticationEventListeners" \
  | python3 -c 'import sys,json,os; listeners=[x["id"] for x in json.load(sys.stdin)["value"] if any(a.get("appId")==os.environ["CLF_APP_ID"] for a in x.get("conditions",{}).get("applications",{}).get("includeApplications",[]))]; print(listeners[0] if listeners else "")')
if [ -z "$EXISTING_LISTENER" ]; then
  curl -s --fail-with-body -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"@odata.type\":\"#microsoft.graph.onTokenIssuanceStartListener\",\"conditions\":{\"applications\":{\"includeApplications\":[{\"appId\":\"$CLF_APP_ID\"}]}},\"handler\":{\"@odata.type\":\"#microsoft.graph.onTokenIssuanceStartCustomExtensionHandler\",\"customExtension\":{\"id\":\"$EXTENSION_ID\"}}}" \
    "$GRAPH/identity/authenticationEventListeners"
fi
echo "DONE"
