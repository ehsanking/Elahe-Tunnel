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
echo -e "${GREEN}   Elahe Tunnel Single-Line Installer    ${NC}"
echo -e "${GREEN}=========================================${NC}"

# 1. Install Dependencies (unzip, curl)
echo -n "Checking dependencies..."
if ! command -v unzip &> /dev/null || ! command -v curl &> /dev/null; then
    echo -e "\n${YELLOW}Installing unzip and curl...${NC}"
    (
        apt-get update -qq && apt-get install -y -qq unzip curl
    ) &
    PID=$!
    spinner $PID
    wait $PID
fi
echo -e " ${GREEN}OK${NC}"

# 2. Check/Install Go
echo -n "Checking Go environment..."
MIN_GO_VERSION="1.24.0"
NEED_GO=false

if command -v go &> /dev/null; then
    INSTALLED_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    # Simple version comparison
    if [ "$(printf '%s\n' "$MIN_GO_VERSION" "$INSTALLED_GO_VERSION" | sort -V | head -n1)" != "$MIN_GO_VERSION" ]; then
        NEED_GO=true
    fi
else
    NEED_GO=true
fi

if [ "$NEED_GO" = true ]; then
    echo -e "\n${YELLOW}Installing Go 1.24+ (from Google Cloud Mirror)...${NC}"
    (
        rm -rf /usr/local/go
        
        # Robust fetch of latest version
        CURL_OPTS="-s -L -A 'Mozilla/5.0' --referer 'https://go.dev/'"
        LATEST_VER=$(curl $CURL_OPTS "https://go.dev/VERSION?m=text" | awk '/^go/ {print $1; exit}' | tr -d '\r')
        
        # Fallback if fetch fails
        if [ -z "$LATEST_VER" ]; then LATEST_VER="go1.24.0"; fi
        
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        
        URL="https://storage.googleapis.com/golang/${LATEST_VER}.linux-${ARCH}.tar.gz"
        
        curl $CURL_OPTS -o /tmp/go.tar.gz "$URL"
        
        if file /tmp/go.tar.gz | grep -q 'gzip'; then
            tar -C /usr/local -xzf /tmp/go.tar.gz
            rm /tmp/go.tar.gz
        else
            exit 1
        fi
    ) &
    
    PID=$!
    spinner $PID
    wait $PID
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install Go.${NC}"
        exit 1
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    echo -e "${GREEN}Go installed successfully.${NC}"
else
    echo -e " ${GREEN}Go is up to date.${NC}"
fi

# Ensure Go is in PATH for this session
export PATH=$PATH:/usr/local/go/bin

# 3. Download Source Code (ZIP method)
echo -n "Downloading Elahe Tunnel source code..."
(
    rm -rf elahe-tunnel-main
    rm -f main.zip
    curl -s -L -o main.zip https://github.com/ehsanking/elahe-tunnel/archive/refs/heads/main.zip
    unzip -q main.zip
) &
PID=$!
spinner $PID
wait $PID

if [ ! -d "elahe-tunnel-main" ]; then
    echo -e "\n${RED}Failed to download source code.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 4. Compile
echo -n "Compiling application..."
cd elahe-tunnel-main
(
    # Use goproxy.io to bypass potential restrictions for modules
    export GOPROXY=https://goproxy.io,direct
    go mod tidy
    go build -o elahe-tunnel -ldflags "-s -w" .
) &
PID=$!
spinner $PID
wait $PID

if [ ! -f "elahe-tunnel" ]; then
    echo -e "\n${RED}Compilation failed.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 5. Install Binary
echo -n "Installing binary..."
mv elahe-tunnel /usr/local/bin/
chmod +x /usr/local/bin/elahe-tunnel
cd ..
rm -rf elahe-tunnel-main main.zip
echo -e " ${GREEN}OK${NC}"

echo -e "\n${GREEN}✅ Installation Complete!${NC}"
echo -e "Starting setup wizard...\n"
sleep 1

# 6. Run Setup
elahe-tunnel setup
