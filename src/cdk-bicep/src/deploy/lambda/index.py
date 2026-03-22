import json
import os
import subprocess
import time
import boto3
import urllib.request
import urllib.parse
import traceback

sts = boto3.client('sts')
s3 = boto3.client('s3')

def handler(event, context):
    """Main handler with CloudFormation response handling"""
    response_url = event.get('ResponseURL')
    
    try:
        request_type = event['RequestType']
        
        if request_type == 'Create':
            result = on_create(event)
        elif request_type == 'Update':
            result = on_update(event)
        elif request_type == 'Delete':
            result = on_delete(event)
        else:
            raise Exception(f'Unknown request type: {request_type}')
        
        # Send success response to CloudFormation
        if response_url:
            send_response(event, context, 'SUCCESS', result)
        return result
        
    except Exception as e:
        print(f'Error: {str(e)}')
        print(traceback.format_exc())
        
        # Send failure response to CloudFormation
        if response_url:
            send_response(event, context, 'FAILED', {
                'PhysicalResourceId': event.get('PhysicalResourceId', 'NONE'),
            }, reason=str(e)[:3000])
        
        raise

def send_response(event, context, status, data, reason=None):
    """Send response to CloudFormation"""
    response_body = {
        'Status': status,
        'Reason': reason or f'See CloudWatch Log Stream: {context.log_stream_name}',
        'PhysicalResourceId': data.get('PhysicalResourceId', context.log_stream_name),
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data.get('Data', {})
    }
    
    json_response = json.dumps(response_body)
    print(f'DEBUG: Response body size: {len(json_response)} bytes')
    print(f'DEBUG: Response body: {json_response[:500]}...')  # Log first 500 chars
    
    headers = {
        'Content-Type': '',
        'Content-Length': str(len(json_response))
    }
    
    req = urllib.request.Request(
        event['ResponseURL'],
        data=json_response.encode('utf-8'),
        headers=headers,
        method='PUT'
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            print(f'CloudFormation response status: {response.status}')
    except Exception as e:
        print(f'Failed to send response to CloudFormation: {str(e)}')

def on_create(event):
    props = event['ResourceProperties']
    
    login_azure_federated(
        props['AzureClientId'],
        props['AzureTenantId'],
        props['AzureSubscriptionId']
    )
    
    deployment_name = props['DeploymentName']
    resource_group = props['ResourceGroupName']
    template_file = props['TemplateFile']
    parameters = json.loads(props['Parameters'])
    
    result = deploy_bicep(deployment_name, resource_group, template_file, parameters)
    
    if props.get('FunctionCodeS3Bucket'):
        deploy_function_code(
            s3_bucket=props['FunctionCodeS3Bucket'],
            s3_key=props['FunctionCodeS3Key'],
            function_app_name=result['outputs']['functionAppName'],
            resource_group=resource_group,
        )
    
    # Only return essential outputs to stay under CloudFormation 4KB response limit
    essential_outputs = {k: v for k, v in result['outputs'].items() if k in ['appId', 'tenantId']}
    
    response_data = {
        'PhysicalResourceId': deployment_name,
        'Data': essential_outputs
    }
    print(f'DEBUG: Returning response data: {json.dumps(response_data, indent=2)}')
    return response_data

def deploy_function_code(s3_bucket, s3_key, function_app_name, resource_group):
    """Upload zip to Azure blob storage, set WEBSITE_RUN_FROM_PACKAGE to SAS URL"""
    zip_path = '/tmp/function-code.zip'

    print(f'Downloading function code from s3://{s3_bucket}/{s3_key}')
    s3.download_file(s3_bucket, s3_key, zip_path)

    # Get storage account name from function app
    result = subprocess.run([
        'az', 'functionapp', 'show',
        '--name', function_app_name,
        '--resource-group', resource_group,
        '--query', 'storageAccountRequired',
        '--output', 'tsv',
    ], capture_output=True, text=True, check=True)

    # Get storage account linked to the function app
    result = subprocess.run([
        'az', 'functionapp', 'config', 'appsettings', 'list',
        '--name', function_app_name,
        '--resource-group', resource_group,
        '--query', "[?name=='AzureWebJobsStorage'].value",
        '--output', 'tsv',
    ], capture_output=True, text=True, check=True)
    conn_str = result.stdout.strip()

    # Extract account name from connection string
    storage_account_name = next(
        part.split('=', 1)[1] for part in conn_str.split(';') if part.startswith('AccountName=')
    )

    container = 'function-releases'
    blob_name = f'{function_app_name}.zip'

    # Create container if it doesn't exist
    subprocess.run([
        'az', 'storage', 'container', 'create',
        '--name', container,
        '--account-name', storage_account_name,
    ], check=True)

    # Upload zip
    subprocess.run([
        'az', 'storage', 'blob', 'upload',
        '--account-name', storage_account_name,
        '--container-name', container,
        '--name', blob_name,
        '--file', zip_path,
        '--overwrite',
    ], check=True)

    # Generate SAS URL with account key (long expiry)
    result = subprocess.run([
        'az', 'storage', 'blob', 'generate-sas',
        '--account-name', storage_account_name,
        '--container-name', container,
        '--name', blob_name,
        '--permissions', 'r',
        '--expiry', '2036-01-01T00:00:00Z',
        '--output', 'tsv',
    ], capture_output=True, text=True, check=True)
    sas_token = result.stdout.strip()

    blob_url = f'https://{storage_account_name}.blob.core.windows.net/{container}/{blob_name}?{sas_token}'

    # Set WEBSITE_RUN_FROM_PACKAGE
    subprocess.run([
        'az', 'functionapp', 'config', 'appsettings', 'set',
        '--name', function_app_name,
        '--resource-group', resource_group,
        '--settings', f'WEBSITE_RUN_FROM_PACKAGE={blob_url}',
    ], check=True)

    print(f'Deployed function code to {function_app_name} via WEBSITE_RUN_FROM_PACKAGE')


def on_update(event):
    return on_create(event)

def on_delete(event):
    """Handle delete - if resource never created successfully, just return success"""
    physical_resource_id = event.get('PhysicalResourceId', 'NONE')
    
    # If the resource was never created (PhysicalResourceId is NONE or missing),
    # just return success without trying to delete anything
    if not physical_resource_id or physical_resource_id == 'NONE':
        return {'PhysicalResourceId': physical_resource_id}
    
    props = event['ResourceProperties']
    deployment_name = physical_resource_id
    
    try:
        login_azure_federated(
            props['AzureClientId'],
            props['AzureTenantId'],
            props['AzureSubscriptionId']
        )
        
        subprocess.run([
            'az', 'deployment', 'group', 'delete',
            '--name', deployment_name,
            '--resource-group', props['ResourceGroupName'],
            '--yes'
        ], check=True)
    except Exception as e:
        # Log the error but don't fail the delete
        # CloudFormation should be able to clean up even if Azure delete fails
        print(f'Warning: Failed to delete Azure deployment: {str(e)}')
    
    return {'PhysicalResourceId': deployment_name}

def login_azure_federated(client_id, tenant_id, subscription_id):
    """Authenticate to Azure using AWS IAM Outbound Identity Federation"""
    
    # Set HOME to /tmp so all tools use writable directory
    os.environ['HOME'] = '/tmp'
    # Set Azure CLI config directory to /tmp (Lambda's writable directory)
    os.environ['AZURE_CONFIG_DIR'] = '/tmp/.azure'
    # Set .NET bundle extract directory to /tmp (required for Bicep)
    os.environ['DOTNET_BUNDLE_EXTRACT_BASE_DIR'] = '/tmp'
    # Run Bicep without globalization support (sufficient for IaC)
    os.environ['DOTNET_SYSTEM_GLOBALIZATION_INVARIANT'] = '1'
    
    # Use AWS IAM Outbound Identity Federation to get a JWT token
    # This requires the feature to be enabled in the AWS account
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound.html
    
    try:
        # GetWebIdentityToken requires specific parameters
        response = sts._make_api_call(
            'GetWebIdentityToken',
            {
                'Audience': ['api://AzureADTokenExchange'],  # Must be a list
                'DurationSeconds': 3600,
                'SigningAlgorithm': 'RS256'  # Required parameter
            }
        )
        
        aws_jwt_token = response['WebIdentityToken']
        
    except Exception as e:
        error_msg = str(e)
        if 'Unknown operation' in error_msg or 'InvalidAction' in error_msg:
            raise Exception(
                'GetWebIdentityToken API not available. '
                'This requires: 1) boto3 version 1.35.36 or later, '
                '2) Outbound identity federation enabled in your AWS account. '
                'See: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html'
            )
        raise Exception(f'Failed to get AWS OIDC token: {error_msg}')
    
    # Login to Azure CLI with the AWS JWT token (federated token)
    # The Azure CLI will exchange this token internally
    subprocess.run([
        'az', 'login',
        '--service-principal',
        '--username', client_id,
        '--tenant', tenant_id,
        '--federated-token', aws_jwt_token
    ], check=True)
    
    # Set subscription
    subprocess.run([
        'az', 'account', 'set',
        '--subscription', subscription_id
    ], check=True)

def wait_for_deployments(resource_group, poll_interval=15, timeout=600):
    """Wait until no deployments in the resource group are in Running state"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run([
            'az', 'deployment', 'group', 'list',
            '--resource-group', resource_group,
            '--query', "[?properties.provisioningState=='Running'].name",
            '--output', 'json'
        ], capture_output=True, text=True, check=True)
        running = json.loads(result.stdout)
        if not running:
            return
        print(f'Waiting for running deployments: {running}')
        time.sleep(poll_interval)
    raise Exception(f'Timed out waiting for running deployments in {resource_group}')

def deploy_bicep(name, resource_group, template_file, parameters):
    # Write template content to a file in /tmp
    template_path = f'/tmp/{name}.bicep'
    with open(template_path, 'w') as f:
        f.write(template_file)
    
    param_args = []
    for key, value in parameters.items():
        param_args.extend(['--parameters', f'{key}={value}'])

    cmd = [
        'az', 'deployment', 'group', 'create',
        '--name', name,
        '--resource-group', resource_group,
        '--template-file', template_path,
        *param_args,
        '--query', '{outputs:properties.outputs}',
        '--output', 'json'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0 and 'DeploymentActive' in result.stderr:
        print('DeploymentActive detected — waiting for running deployments to finish')
        wait_for_deployments(resource_group)
        result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        error_msg = f'Bicep deployment failed.\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}'
        print(error_msg)
        raise Exception(error_msg)
    
    deployment = json.loads(result.stdout)
    print(f'DEBUG: Deployment response: {json.dumps(deployment, indent=2)}')
    
    outputs = {}
    deployment_outputs = deployment.get('outputs', {})
    print(f'DEBUG: Deployment outputs: {json.dumps(deployment_outputs, indent=2)}')
    
    for key, value in deployment_outputs.items():
        outputs[key] = value['value']
    
    print(f'DEBUG: Extracted outputs: {json.dumps(outputs, indent=2)}')
    return {'outputs': outputs}
