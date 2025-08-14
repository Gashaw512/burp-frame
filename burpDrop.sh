#!/bin/bash

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 not found"
    echo "Please install Python 3: https://www.python.org/downloads/"
    exit 1
fi

# Install dependencies
echo "Checking dependencies..."
python3 -m pip install -q -r "$SCRIPT_DIR/scripts/requirements.txt"
if [ $? -ne 0 ]; then
    echo "⚠ Warning: Failed to install some dependencies"
    echo "Continuing anyway..."
fi

# Launch application as a package
echo "🚀 Starting burpDrop..."
python3 -m scripts.main "$@"