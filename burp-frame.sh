#!/usr/bin/env bash

# =======================================================
# 🚀 burp-frame.sh - Cross-platform Linux/macOS Launcher
# =======================================================

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}🚀 Starting burp-frame Launcher${NC}"
echo -e "${CYAN}========================================${NC}"

# 1️⃣ Check Python installation
if command -v python3 &>/dev/null; then
    PYTHON_BIN=python3
elif command -v python &>/dev/null; then
    PYTHON_BIN=python
else
    echo -e "${RED}❌ Python is not installed.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Python found: $($PYTHON_BIN --version)${NC}"

# 2️⃣ Upgrade pip
echo -e "${CYAN}Checking and upgrading pip...${NC}"
$PYTHON_BIN -m pip install --upgrade pip setuptools wheel &>/dev/null
echo -e "${GREEN}✅ Pip ready.${NC}"

# 3️⃣ Install dependencies
echo -e "${CYAN}Installing/verifying project dependencies...${NC}"
$PYTHON_BIN -m pip install -r burp_frame/requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to install dependencies.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Dependencies installed.${NC}"

# 4️⃣ Install/verify the package itself
echo -e "${CYAN}Installing/verifying burp-frame package...${NC}"
$PYTHON_BIN -m pip install --upgrade .
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to install burp-frame package.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Package installed successfully.${NC}"

# 5️⃣ Launch CLI
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}🚀 Launching burp-frame...${NC}"
echo -e "${CYAN}========================================${NC}"

$PYTHON_BIN -m burp_frame.cli "$@"

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo -e "${RED}❌ burp-frame exited with errors.${NC}"
else
    echo -e "${GREEN}✅ burp-frame exited successfully.${NC}"
fi

exit $EXIT_CODE
