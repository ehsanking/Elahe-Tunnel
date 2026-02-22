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

# 1. Install Dependencies (unzip, curl, file)
echo -n "Checking dependencies..."
if ! command -v unzip &> /dev/null || ! command -v curl &> /dev/null || ! command -v file &> /dev/null; then
    echo -e "\n${YELLOW}Installing unzip, curl, and file...${NC}"
    (
        apt-get update -qq && apt-get install -y -qq unzip curl file
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
    echo -e "\n${YELLOW}Installing Go 1.24.0...${NC}"
    (
        rm -rf /usr/local/go
        
        LATEST_VER="go1.24.0"
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        
        # 1. Check for local file (Manual Upload Method)
        if [ -f "go.tar.gz" ]; then
            echo "Found local go.tar.gz, using it..."
            cp go.tar.gz /tmp/go.tar.gz
        else
            # 2. Try User-Provided Google Drive Link
            GDRIVE_ID="11cP6W4zsH86EoidAxZGcGhqnVbeGd0AR"
            echo "Attempting download from Google Drive (User Link)..."
            
            URL="https://drive.google.com/uc?export=download&id=${GDRIVE_ID}"
            
            # Initial request to handle confirmation token
            curl -c /tmp/cookies -s -L "$URL" > /tmp/response
            # Extract confirmation token if present
            CONFIRM=$(grep -o 'confirm=[a-zA-Z0-9]*' /tmp/response | cut -d= -f2 | head -n1)
            
            if [ -n "$CONFIRM" ]; then
                echo "  (Sending download confirmation...)"
                curl -b /tmp/cookies -s -L -o /tmp/go.tar.gz "${URL}&confirm=${CONFIRM}"
            else
                mv /tmp/response /tmp/go.tar.gz
            fi
            rm -f /tmp/cookies /tmp/response

            # Verify GDrive download
            if ! file /tmp/go.tar.gz | grep -q 'gzip'; then
                echo "⚠️ Google Drive download failed or blocked. Trying Aliyun Mirror..."
                
                # 3. Fallback to Aliyun Mirror
                URL="https://mirrors.aliyun.com/golang/${LATEST_VER}.linux-${ARCH}.tar.gz"
                echo "Downloading from Aliyun Mirror ($URL)..."
                
                if ! curl -L -A 'Mozilla/5.0' -o /tmp/go.tar.gz "$URL"; then
                    echo "❌ All download methods failed." >&2
                    exit 1
                fi
            else
                echo "✅ Downloaded successfully from Google Drive."
            fi
        fi
        
        # Verify and Install
        if file /tmp/go.tar.gz | grep -q 'gzip'; then
            tar -C /usr/local -xzf /tmp/go.tar.gz
            rm /tmp/go.tar.gz
        else
            echo "File is not a valid gzip archive." >&2
            exit 1
        fi
    ) &
    
    PID=$!
    spinner $PID
    wait $PID
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install Go. Check your internet connection.${NC}"
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
