#!/bin/bash
set -e

echo 'Configuring AWS...'

# Get GitHub username, repo name, and branch
GH_USER=${GITHUB_USER:-$(whoami)}
REPO_NAME=${GITHUB_REPOSITORY_NAME:-"q-for-cdk-aws-template"}
BRANCH_NAME=$(git -C /workspaces/q-for-cdk-aws-template rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
USERNAME="$GH_USER-$REPO_NAME-$BRANCH_NAME"
echo "Using username: $USERNAME"

# AWS configuration
mkdir -p /home/node/.aws
cat > /home/node/.aws/config << EOF
[sso-session $USERNAME]
sso_start_url = https://raindancers.awsapps.com/start#
sso_region = ap-southeast-2
sso_registration_scopes = sso:account:access

[profile changeme]
sso_session = $USERNAME
sso_account_id = 123456789000
sso_role_name = notArealRole
region = ap-southeast-2

[profile oneBot]
sso_session = $USERNAME
sso_account_id = 555108417648
sso_role_name = oneBot_QDevPro
region = ap-southeast-2
EOF

echo 'AWS configuration completed'