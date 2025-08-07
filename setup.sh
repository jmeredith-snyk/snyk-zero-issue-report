#!/bin/bash

echo "Setting up Snyk Issue Reporter..."

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

echo "Python 3 found: $(python3 --version)"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
else
    echo "Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "Creating .env template..."
    cat > .env << EOF
SNYK_TOKEN="your_snyk_api_token_here"

# Optional: Multiple organization IDs (for interactive mode)
# SNYK_ORG_IDS="org-id-1,org-id-2,org-id-3"

# Optional: Multiple group IDs (for interactive mode)
# SNYK_GROUP_IDS="group-id-1,group-id-2,group-id-3"
EOF
    echo "Please edit .env file with your Snyk API token and optional organization/group IDs"
else
    echo ".env file already exists"
fi

echo ""
echo "Setup complete."
echo "Run: python3 snyk_issue_reporter.py --help" 