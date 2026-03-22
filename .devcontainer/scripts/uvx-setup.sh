#!/bin/bash

echo "Installing uvx..."

# Install uv first (uvx is part of uv)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add uv to PATH for current session
export PATH="$HOME/.cargo/bin:$PATH"

# Add to shell profile for persistence
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc

echo "uvx installation completed"