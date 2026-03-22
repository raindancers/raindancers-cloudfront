import azure.functions as func
import logging
import json
import asyncio
from azure.identity import DefaultAzureCredential
from msgraph import GraphServiceClient

app = func.FunctionApp()

@app.function_name(name="CustomClaimsProvider")
@app.route(route="CustomClaimsProvider", auth_level=func.AuthLevel.ANONYMOUS)
async def token_issuance_start(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function for Custom Claims Provider - Token Issuance Start Event
    
    Receives token issuance event from Azure AD, queries user's app role assignments,
    and returns separate AWS session tag claims for each role.
    """
    logging.info('Token issuance start event received')
    
    try:
        # Parse request body from Azure AD
        req_body = req.get_json()
        
        # Extract user ID and application service principal ID from authentication context
        user_id = req_body['data']['authenticationContext']['user']['id']
        app_service_principal_id = req_body['data']['authenticationContext']['clientServicePrincipal']['id']
        
        logging.info(f'Processing token issuance for user: {user_id}, app: {app_service_principal_id}')
        
        # Get user's app role assignments from Microsoft Graph API
        roles = await get_user_roles(user_id, app_service_principal_id)
        
        claims = {}
        if roles:
            claims['Roles'] = ':' + ':'.join(roles) + ':'
        logging.info(f'Emitting Roles claim: {claims.get("Roles", "(empty)")}')
        
        # Return response in format Azure AD expects
        response = {
            "data": {
                "@odata.type": "microsoft.graph.onTokenIssuanceStartResponseData",
                "actions": [
                    {
                        "@odata.type": "microsoft.graph.tokenIssuanceStart.provideClaimsForToken",
                        "claims": claims
                    }
                ]
            }
        }
        
        return func.HttpResponse(
            body=json.dumps(response),
            mimetype="application/json",
            status_code=200
        )
        
    except Exception as e:
        logging.error(f'Error processing token issuance event: {str(e)}')
        # Return empty claims on error to allow authentication to proceed
        return create_empty_response()


async def get_user_roles(user_id: str, app_service_principal_id: str) -> list:
    """
    Query Microsoft Graph API to get user's app role assignments for a specific application.
    
    Uses Managed Identity (DefaultAzureCredential) for authentication.
    Returns list of role display names (e.g., ["Animals", "PowerUsers"]).
    
    Args:
        user_id: User's object ID
        app_service_principal_id: Service principal ID of the application requesting the token
    """
    try:
        # Authenticate using Managed Identity
        credential = DefaultAzureCredential()
        scopes = ['https://graph.microsoft.com/.default']
        
        # Create Graph API client
        client = GraphServiceClient(credentials=credential, scopes=scopes)
        
        # Query user's app role assignments
        # GET /users/{user-id}/appRoleAssignments
        result = await client.users.by_user_id(user_id).app_role_assignments.get()
        
        if not result or not result.value:
            logging.info(f'No app role assignments found for user {user_id}')
            return []
        
        # Extract role display names from assignments for THIS application only
        roles = []
        for assignment in result.value:
            # Only process assignments for the application requesting the token
            if str(assignment.resource_id) == app_service_principal_id:
                app_role_id = assignment.app_role_id
                
                if app_role_id:
                    role_name = await get_role_name(client, app_service_principal_id, app_role_id)
                    if role_name:
                        roles.append(role_name)
        
        logging.info(f'Found {len(roles)} roles for user {user_id}: {roles}')
        return roles
        
    except Exception as e:
        logging.error(f'Error querying user roles from Graph API: {str(e)}')
        return []


async def get_role_name(client: GraphServiceClient, resource_id: str, app_role_id: str) -> str:
    """
    Get role display name by querying the service principal's app role definitions.
    
    Args:
        client: Graph API client
        resource_id: Service principal object ID
        app_role_id: App role ID (GUID)
    
    Returns:
        Role display name (e.g., "Animals") or None if not found
    """
    try:
        # GET /servicePrincipals/{resource-id}
        service_principal = await client.service_principals.by_service_principal_id(resource_id).get()
        
        if not service_principal or not service_principal.app_roles:
            return None
        
        # Find the app role by ID
        for app_role in service_principal.app_roles:
            if str(app_role.id) == str(app_role_id):
                return app_role.display_name
        
        return None
        
    except Exception as e:
        logging.error(f'Error getting role name: {str(e)}')
        return None


def create_empty_response() -> func.HttpResponse:
    """
    Create response with empty claims object.
    Used when no roles found or error occurs.
    """
    response = {
        "data": {
            "@odata.type": "microsoft.graph.onTokenIssuanceStartResponseData",
            "actions": [
                {
                    "@odata.type": "microsoft.graph.tokenIssuanceStart.provideClaimsForToken",
                    "claims": {}
                }
            ]
        }
    }
    
    return func.HttpResponse(
        body=json.dumps(response),
        mimetype="application/json",
        status_code=200
    )

