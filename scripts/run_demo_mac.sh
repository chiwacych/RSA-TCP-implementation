#!/bin/bash
# ===========================
# RSA TCP Demo Launcher - macOS
# ===========================
# This script automatically launches both Alice and Bob GUIs in separate Terminal windows
# for easy demonstration of RSA over TCP communication.

# Colors for output
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}   RSA over TCP - Demo Launcher (macOS)       ${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# Get script directory and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Check if virtual environment exists
VENV_PATH="$PROJECT_ROOT/rsa_tcp_impl_env"
if [ -d "$VENV_PATH" ]; then
    PYTHON_EXE="$VENV_PATH/bin/python"
    echo -e "${GREEN}✓ Using virtual environment${NC}"
else
    PYTHON_EXE="python3"
    echo -e "${YELLOW}⚠ Virtual environment not found, using system Python${NC}"
fi

# Paths to GUI scripts
ALICE_SCRIPT="$PROJECT_ROOT/alice_gui.py"
BOB_SCRIPT="$PROJECT_ROOT/bob_gui.py"

# Check if scripts exist
if [ ! -f "$ALICE_SCRIPT" ]; then
    echo -e "${RED}✗ Error: alice_gui.py not found!${NC}"
    exit 1
fi
if [ ! -f "$BOB_SCRIPT" ]; then
    echo -e "${RED}✗ Error: bob_gui.py not found!${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}Launching Alice GUI (Server)...${NC}"
echo -e "${GRAY}  - Alice will run on port 3000 (configurable in GUI)${NC}"
echo -e "${GRAY}  - Change to port 5000 if you get permission errors${NC}"

# Launch Alice in new Terminal window using osascript
osascript <<EOF
tell application "Terminal"
    do script "cd '$PROJECT_ROOT' && '$PYTHON_EXE' '$ALICE_SCRIPT'"
    activate
end tell
EOF

# Wait a moment for Alice to start
sleep 2

echo ""
echo -e "${CYAN}Launching Bob GUI (Client)...${NC}"
echo -e "${GRAY}  - Bob will connect to localhost:3000 by default${NC}"
echo -e "${GRAY}  - Update port in GUI if Alice uses different port${NC}"

# Launch Bob in new Terminal window using osascript
osascript <<EOF
tell application "Terminal"
    do script "cd '$PROJECT_ROOT' && '$PYTHON_EXE' '$BOB_SCRIPT'"
    activate
end tell
EOF

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}✓ Both GUIs launched successfully!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "${NC}  1. In Alice's window: Generate Keys → Start Server${NC}"
echo -e "${NC}  2. In Bob's window: Generate Keys → Connect to Alice${NC}"
echo -e "${NC}  3. Send encrypted messages between Alice and Bob!${NC}"
echo ""
echo -e "${GRAY}Terminal windows will remain open after GUIs close.${NC}"
echo ""
echo -e "${GRAY}You can close this launcher window now.${NC}"
