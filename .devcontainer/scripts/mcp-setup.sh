#!/bin/bash
set -e

echo 'Configuring MCP...'

# Create AWS amazonq directory and MCP configuration
mkdir -p /home/node/.aws/amazonq
cat > /home/node/.aws/amazonq/mcp.json << EOF
{
  "mcpServers": {
    "aws-knowledge-mcp-server": {
      "url": "https://knowledge-mcp.global.api.aws"
    },
    "awslabs.aws-api-mcp-server": {
      "command": "uvx",
      "args": [
        "awslabs.aws-api-mcp-server@latest"
      ],
      "env": {
        "AWS_REGION": "ap-southeast-2"
      },
      "disabled": false,
      "autoApprove": []
    },
    "awslabs.aws-pricing-mcp-server": {
      "command": "uvx",
      "args": [
        "awslabs.aws-pricing-mcp-server@latest"
      ],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR",
        "AWS_REGION": "ap-southeast-2"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
EOF

echo 'MCP configuration completed'