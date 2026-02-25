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
echo -e "${GREEN}   Elahe Tunnel Single-Line Installer v1.0.0 (Final) ${NC}"
echo -e "${GREEN}=========================================${NC}"

# 1. Install Dependencies
apt-get update -qq && apt-get install -y -qq unzip curl file lsof psmisc &> /dev/null

# --- Port Check Function ---
check_and_free_port_443() {
    echo -n "Checking port 443..."
    if lsof -i :443 > /dev/null; then
        echo -e "${YELLOW} Port 443 is busy. Attempting to free it...${NC}"
        
        # Get PID
        PID=$(lsof -t -i:443)
        if [ -n "$PID" ]; then
            echo -e "Killing process $PID using port 443..."
            kill -9 $PID 2>/dev/null || true
            sleep 2
        fi
        
        # Double check
        if lsof -i :443 > /dev/null; then
             echo -e "${RED} Failed to free port 443. Please manually stop the service (e.g., nginx, apache) using it.${NC}"
             echo -e "${RED} Run: sudo systemctl stop nginx (or apache2)${NC}"
        else
             echo -e "${GREEN} Port 443 is now free and reserved for Elahe Tunnel.${NC}"
        fi
    else
        echo -e "${GREEN} Port 443 is free.${NC}"
    fi
}

# Enable TCP Fast Open in kernel
if [ -f /proc/sys/net/ipv4/tcp_fastopen ]; then
    echo 3 > /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null || true
fi

# 2. Download Source Code (if not already present)
if [ -f "go.mod" ] && [ -f "main.go" ]; then
    echo "Detected source code in current directory. Skipping download."
    SOURCE_DIR="."
else
    echo -n "Downloading Elahe Tunnel source code..."
    (
        rm -rf Elahe-Tunnel-main elahe-tunnel-main main.zip
        curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip" || \
        curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://mirror.ghproxy.com/https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip"
        unzip -o -q main.zip
    ) &> /dev/null &
    spinner $!
    wait $!

    if [ -d "Elahe-Tunnel-main" ]; then
        SOURCE_DIR="Elahe-Tunnel-main"
    elif [ -d "elahe-tunnel-main" ]; then
        SOURCE_DIR="elahe-tunnel-main"
    else
        echo -e "\n${RED}Failed to download source code.${NC}"
        exit 1
    fi
    echo -e " ${GREEN}OK${NC}"
fi

# 3. Install Go
if ! command -v go &> /dev/null || [ "$(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f2)" -lt 22 ]; then
    echo -n "Installing Go 1.22.2..."
    (
        rm -rf /usr/local/go
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        URL="https://go.dev/dl/go1.22.2.linux-${ARCH}.tar.gz"
        curl -L -o /tmp/go.tar.gz "$URL"
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
    ) &> /dev/null &
    spinner $!
    wait $!
    echo -e " ${GREEN}OK${NC}"
fi
export PATH=/usr/local/go/bin:$PATH

# 4. Compile
echo -n "Compiling..."
if [ "$SOURCE_DIR" != "." ]; then
    cd "$SOURCE_DIR"
fi

( 
    export GOPROXY=https://goproxy.io,direct
    export GOTOOLCHAIN=local
    go mod tidy
    go build -o elahe-tunnel -ldflags "-s -w" .
) &
spinner $!
wait $!

if [ ! -f "elahe-tunnel" ]; then
    echo -e "\n${RED}Compilation failed.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 5. Install Binary and Cleanup
echo -n "Installing binary..."
mv elahe-tunnel /usr/local/bin/
chmod +x /usr/local/bin/elahe-tunnel

if [ "$SOURCE_DIR" != "." ]; then
    cd ..
    rm -rf "$SOURCE_DIR" main.zip
fi
echo -e " ${GREEN}OK${NC}"

# 6. Run Setup
echo -e "\n${GREEN}✅ Installation Complete!${NC}"

if [ -t 0 ]; then
    echo -e "Starting setup wizard...\n"
    sleep 1
    elahe-tunnel setup
else
    echo -e "Non-interactive mode detected. Skipping setup wizard."
    echo -e "Run 'elahe-tunnel setup' manually to configure."
fi
