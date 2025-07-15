#!/usr/bin/env bash
# Exit on error
set -o errexit

# Use Python 3.11
echo "Using Python 3.11"
export PYTHON_VERSION=3.11.8

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Print verification
python --version
echo "Build completed successfully"