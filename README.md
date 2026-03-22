# DevContainer Setup

This directory contains the configuration and setup scripts for the development container environment.

## Overview

The devcontainer is based on the TypeScript/Node.js 22 image and includes AWS development tools, Python, and Docker support.

## WSL2 Setup for Optimal Performance

**Recommended**: Clone and work with this repository directly in WSL2 for significantly better performance (5-10x faster than Windows filesystem access).

### Prerequisites
- Windows 10/11 with WSL2 enabled
- Docker Desktop for Windows with WSL2 backend enabled
- VS Code with Remote Development extension pack installed

### Setup Steps

1. **Open a WSL2 terminal** (e.g., Ubuntu from Windows Terminal)

2. **Clone the repository in WSL2 filesystem**:
   ```bash
   cd ~
   git clone <repository-url>
   cd cdk-api
   ```

3. **Open in VS Code**:
   ```bash
   code .
   ```
   
4. **Reopen in Container**: When prompted by VS Code, click "Reopen in Container"
   - Or use Command Palette: `Dev Containers: Reopen in Container`

### GitHub CLI Setup

If you need to clone private repositories or authenticate with GitHub from within WSL2, you may need to install GitHub CLI:

1. **Open Windows Terminal and access your WSL2 distro as root**:
   ```bash
   wsl -u root
   ```

2. **Install GitHub CLI**:
   ```bash
   apt update && apt install gh
   ```

3. **Exit root and authenticate** (as your regular user):
   ```bash
   exit
   gh auth login
   ```
   
   Follow the prompts and select:
   - **GitHub.com**
   - **HTTPS** protocol
   - **Login with a web browser** (device code flow)
   - Copy the one-time code and press Enter to open the browser
   - Paste the code in GitHub to complete authentication

**Note**: This installs `gh` in your WSL2 distro, not in the devcontainer. The devcontainer will inherit your WSL2 git credentials when cloning repositories.

### Verify Your Setup

To confirm you're running with optimal performance:

```bash
# Check filesystem type (should show ext4, not 9p)
df -h /workspaces/cdk-api

# Check kernel (should show WSL2)
uname -a
```

**Expected output**: `/dev/sd*` device with `ext4` filesystem and `microsoft-standard-WSL2` kernel.

### Architecture

Your development environment runs as: **Windows → WSL2 → Docker → Dev Container**

- Files are stored natively in WSL2's ext4 filesystem (not Windows NTFS)
- Docker engine runs in WSL2
- Dev container runs in Docker with direct access to WSL2 filesystem
- Result: Native Linux I/O performance for operations like `npm install` and `yarn`

### Note on Remote Explorer

The devcontainer will appear under **Dev Containers** in VS Code Remote Explorer, not under WSL Targets. This is correct - you're connected to the container, which is hosted by Docker in WSL2.

## Setup Process

When the devcontainer is created, the `postCreateCommand` runs:
```bash
chmod +x .devcontainer/setup.sh .devcontainer/scripts/*.sh && .devcontainer/setup.sh
```

This command:
1. Makes all shell scripts executable (`chmod +x`)
2. Runs the main setup script (`setup.sh`) only if the chmod succeeds (`&&`)

## What Gets Installed

### Base Features
- **TypeScript/Node.js 22**: Main development environment
- **AWS CLI**: Command line interface for AWS services
- **Docker-in-Docker**: Ability to run Docker containers within the devcontainer
- **Python**: Python runtime and tools

### VS Code Extensions
- TypeScript language support
- AWS Toolkit for VS Code
- Amazon Q for VS Code
- GitHub Actions support
- JSON language support
- Python language support and linting

### Setup Scripts

The main `setup.sh` orchestrates the following individual setup scripts:

#### 1. NPM Setup (`scripts/npm-setup.sh`)
- Configures NPM for GitHub packages
- Sets up authentication token for `@tepapaatawhai` scope
- Creates `.npmrc` configuration

#### 2. Dependencies Installation (`scripts/install-deps.sh`)
- Runs `yarn install` to install project dependencies

#### 3. AWS Setup (`scripts/aws-setup.sh`)
- Creates AWS configuration directory
- Sets up AWS SSO profile configuration
- Configures default region (ap-southeast-2)
- **Note**: Contains placeholder values that need to be updated

#### 4. MCP Setup (`scripts/mcp-setup.sh`)
- Configures Model Context Protocol for Amazon Q
- Sets up filesystem, git, and AWS MCP servers
- Creates configuration in `~/.config/amazonq/mcp.json`

## Configuration Files

- `devcontainer.json`: Main devcontainer configuration
- `setup.sh`: Main setup orchestrator
- `scripts/`: Individual setup scripts for different components

## User

The container runs as the `node` user for several important reasons:
- **Security**: Avoids running as root, following the principle of least privilege
- **Compatibility**: Pre-configured with proper permissions for Node.js development and NPM/Yarn package management
- **Standards**: Follows Node.js Docker image conventions and integrates well with VS Code devcontainers
- **Environment**: Provides a proper home directory (`/home/node`) for configuration files and shell access


## Known Issues

### MCP Setup
The Model Context Protocol (MCP) setup is not 100% configured correctly. Some manual configuration may be required after the devcontainer is created.

### Git LFS
The repository is configured for Git LFS but `git-lfs` is not installed in the devcontainer. You may see warnings about missing Git LFS. To resolve, either:
- Install Git LFS: `sudo apt-get update && sudo apt-get install git-lfs`
- Or remove Git LFS hooks if not needed: `rm .git/hooks/post-commit`

## Logs

Setup progress is logged to `~/setup.log` for troubleshooting.

## Customization

To modify the setup:
1. Edit the relevant script in the `scripts/` directory
2. Update AWS configuration in `aws-setup.sh` with your actual values
3. Modify NPM configuration in `npm-setup.sh` if using different registries
4. Rebuild the devcontainer to apply changes

**Adding New Scripts**: You can create additional setup scripts in the `scripts/` directory. They will automatically be made executable by the `postCreateCommand`. Remember to call your new script from `setup.sh` to include it in the setup process.template
