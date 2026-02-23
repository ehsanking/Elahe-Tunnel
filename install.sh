#!/bin/bash

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Spinner Function ---
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}   Elahe Tunnel Single-Line Installer v2.0 (Final) ${NC}"
echo -e "${GREEN}=========================================${NC}"

# 1. Install Dependencies
echo -n "Checking dependencies..."
if ! command -v unzip &> /dev/null || ! command -v curl &> /dev/null || ! command -v file &> /dev/null; then
    echo -e "\n${YELLOW}Installing dependencies...${NC}"
    (apt-get update -qq && apt-get install -y -qq unzip curl file) &> /dev/null &
    spinner $!
    wait $!
fi
echo -e " ${GREEN}OK${NC}"

# 2. Download Source Code
echo -n "Downloading Elahe Tunnel source code..."
(
    rm -rf Elahe-Tunnel-main elahe-tunnel-main main.zip
    curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip" || \
    curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://mirror.ghproxy.com/https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip"
    unzip -o -q main.zip
) &
PID=$!
spinner $PID
wait $PID

if [ -d "Elahe-Tunnel-main" ]; then
    SOURCE_DIR="Elahe-Tunnel-main"
elif [ -d "elahe-tunnel-main" ]; then
    SOURCE_DIR="elahe-tunnel-main"
else
    echo -e "\n${RED}Failed to download source code.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"


# 3. Check/Install Go
echo -n "Checking Go environment..."
export PATH=/usr/local/go/bin:$PATH
MIN_GO_VERSION="1.24.0"
NEED_GO=false
if command -v go &> /dev/null; then
    INSTALLED_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if [ "$(printf '%s\n' "$MIN_GO_VERSION" "$INSTALLED_GO_VERSION" | sort -V | head -n1)" != "$MIN_GO_VERSION" ]; then
        NEED_GO=true
        echo -e " ${YELLOW}(Found version $INSTALLED_GO_VERSION, need $MIN_GO_VERSION)${NC}"
    else
        echo -e " ${GREEN}Found Go $INSTALLED_GO_VERSION (OK)${NC}"
    fi
else
    NEED_GO=true
    echo -e " ${YELLOW}(Go not found)${NC}"
fi

if [ "$NEED_GO" = true ]; then
    echo -e "\n${YELLOW}Installing Go $MIN_GO_VERSION...${NC}"
    (
        rm -rf /usr/local/go
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        URL="https://go.dev/dl/go${MIN_GO_VERSION}.linux-${ARCH}.tar.gz"
        curl -L -o /tmp/go.tar.gz "$URL"
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
    ) &
    PID=$!
    spinner $PID
    wait $PID
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install Go.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Go installed successfully.${NC}"
fi

export PATH=/usr/local/go/bin:$PATH

# 4. Compile
echo -n "Compiling application..."
cd "$SOURCE_DIR"

# Execute the web panel patch script if it exists
if [ -f "/tmp/patch.sh" ]; then
    chmod +x /tmp/patch.sh
    /tmp/patch.sh
fi

( 
    export GOPROXY=https://goproxy.io,direct
    export GOTOOLCHAIN=local
    go mod tidy
    go build -o elahe-tunnel -ldflags "-s -w" .
) &
PID=$!
spinner $PID
wait $PID

if [ ! -f "elahe-tunnel" ]; then
    echo -e "\n${RED}Compilation failed.${NC}"
    # Print last 20 lines of build log
    go build -o elahe-tunnel -ldflags "-s -w" . > /tmp/build_log.txt 2>&1
    tail -n 20 /tmp/build_log.txt
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 5. Install Binary
echo -n "Installing binary..."
mv elahe-tunnel /usr/local/bin/
chmod +x /usr/local/bin/elahe-tunnel

# Cleanup
cd ..
rm -rf "$SOURCE_DIR" main.zip
rm -f /tmp/patch.sh
echo -e " ${GREEN}OK${NC}"

echo -e "\n${GREEN}✅ Installation Complete!${NC}"
echo -e "Starting setup wizard...\n"
sleep 1

# 6. Run Setup
echo -e "\n${YELLOW}--- Setup Wizard ---${NC}"
echo "Please select the node type:"
echo "1) External (Server - Outside Iran)"
echo "2) Internal (Client - Inside Iran)"
read -p "Enter choice [1-2]: " choice

case $choice in
    1)
        elahe-tunnel setup external
        ;;
    2)
        elahe-tunnel setup internal
        ;;
    *)
        echo -e "${RED}Invalid choice.${NC}"
        echo -e "Please run '${GREEN}elahe-tunnel setup external${NC}' or '${GREEN}elahe-tunnel setup internal${NC}' manually."
        ;;
esac
