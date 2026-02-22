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
echo -e "${GREEN}   Elahe Tunnel Single-Line Installer v1.1 ${NC}"
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

# 2. Download Source Code (Moved up to check for bundled Go)
echo -n "Downloading Elahe Tunnel source code..."

# Check if running inside source directory
if [ -f "go.mod" ] && [ -f "main.go" ]; then
    echo -e " ${GREEN}Running inside source directory. Skipping download.${NC}"
    SOURCE_DIR="."
else
    (
        rm -rf Elahe-Tunnel-main elahe-tunnel-main
        
        # 1. Check for local manual upload
        if [ -f "main.zip" ] && unzip -tq main.zip >/dev/null 2>&1; then
            echo "Found local main.zip..." >> /dev/null
        else
            rm -f main.zip
            # 2. Direct Download
            if ! curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip"; then
                 rm -f main.zip
            fi
            
            # 3. Proxy Download (if direct failed)
            if [ ! -f "main.zip" ] || ! unzip -tq main.zip >/dev/null 2>&1; then
                rm -f main.zip
                # Using ghproxy mirror
                curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://mirror.ghproxy.com/https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip"
            fi
        fi

        # Extract with overwrite (-o)
        if unzip -tq main.zip >/dev/null 2>&1; then
            unzip -o -q main.zip
        else
            exit 1
        fi
    ) &
    PID=$!
    spinner $PID
    wait $PID

    if [ -d "Elahe-Tunnel-main" ]; then
        SOURCE_DIR="Elahe-Tunnel-main"
    elif [ -d "elahe-tunnel-main" ]; then
        SOURCE_DIR="elahe-tunnel-main"
    else
        echo -e "\n${RED}Failed to download source code. GitHub might be blocked.${NC}"
        echo -e "${YELLOW}Solution: Download 'main.zip' from GitHub manually and upload it here.${NC}"
        exit 1
    fi
    echo -e " ${GREEN}OK${NC}"
fi

# 3. Check/Install Go
echo -n "Checking Go environment..."
# Add potential Go path to PATH for check
export PATH=/usr/local/go/bin:$PATH

MIN_GO_VERSION="1.24.0"
NEED_GO=false

if command -v go &> /dev/null; then
    INSTALLED_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    # Simple version comparison
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
    echo -e "\n${YELLOW}Installing Go 1.24.0...${NC}"
    (
        rm -rf /usr/local/go
        
        LATEST_VER="go1.24.0"
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        
        # 1. Check for bundled Go in resources/ (Best for offline/bundled install)
        if [ -f "$SOURCE_DIR/resources/go.tar.gz" ]; then
            echo "Found bundled Go in resources/go.tar.gz, using it..."
            cp "$SOURCE_DIR/resources/go.tar.gz" /tmp/go.tar.gz
        # 2. Check for local file (Manual Upload Method in root)
        elif [ -f "go.tar.gz" ]; then
            echo "Found local go.tar.gz in root, using it..."
            cp go.tar.gz /tmp/go.tar.gz
        else
            # 3. Try User's GitHub Release (Primary Online Method)
            URL="https://github.com/ehsanking/Elahe-Tunnel/releases/download/Go_1.24/go.tar.gz"
            echo "Downloading Go 1.24 from GitHub Release..."
            
            # Try downloading from GitHub (Timeout reduced to 10s connection, 600s max transfer)
            if ! curl -L -A 'Mozilla/5.0' --connect-timeout 10 --max-time 600 -o /tmp/go.tar.gz "$URL"; then
                echo "⚠️ GitHub download failed or timed out. Switching to Aliyun Mirror..."
                
                # 4. Fallback to Aliyun Mirror
                URL="https://mirrors.aliyun.com/golang/${LATEST_VER}.linux-${ARCH}.tar.gz"
                echo "Downloading from Aliyun Mirror ($URL)..."
                
                if ! curl -L -A 'Mozilla/5.0' -o /tmp/go.tar.gz "$URL"; then
                    echo "❌ All download methods failed." >&2
                    exit 1
                fi
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

# Ensure Go is in PATH for this session (Prepend to take precedence over system Go)
export PATH=/usr/local/go/bin:$PATH

# 4. Compile
echo -n "Compiling application..."

# Enter directory
cd "$SOURCE_DIR"

# --- HOTFIX: Patch Source Code Bugs ---
echo -n "Patching source code..."

# 1. Fix internal/pool/pool.go (undefined: err)
if [ -f "internal/pool/pool.go" ]; then
    sed -i 's/if conn.SetReadDeadline(time.Now().Add(1 \* time.Millisecond)); err != nil {/if err := conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {/' internal/pool/pool.go
    sed -i 's/if conn.SetReadDeadline(time.Time{}); err != nil {/if err := conn.SetReadDeadline(time.Time{}); err != nil {/' internal/pool/pool.go
fi

# 2. Fix internal/tunnel/ping.go (undefined: WrapInHttpResponse)
if [ -f "internal/tunnel/ping.go" ]; then
    sed -i 's/masquerade.WrapInHttpResponse/masquerade.WrapInRandomHttpResponse/' internal/tunnel/ping.go
fi

# 3. Fix internal/tunnel/client.go (unused import, variable shadowing)
if [ -f "internal/tunnel/client.go" ]; then
    # Remove unused import
    sed -i '/"github.com\/google\/uuid"/d' internal/tunnel/client.go
    # Fix err shadowing in manageConnection
    # We replace the specific block where shadowing happens
    sed -i 's/encryptedPong, err := masquerade.UnwrapFromHttpResponse(resp)/var encryptedPong []byte; encryptedPong, err = masquerade.UnwrapFromHttpResponse(resp)/' internal/tunnel/client.go
    sed -i 's/pong, err := crypto.Decrypt(encryptedPong, key)/var pong []byte; pong, err = crypto.Decrypt(encryptedPong, key)/' internal/tunnel/client.go
    sed -i 's/resp, err := httpClient.Do(req)/var resp *http.Response; resp, err = httpClient.Do(req)/' internal/tunnel/client.go
fi

# 4. Fix internal/tunnel/server.go (Major fixes)
if [ -f "internal/tunnel/server.go" ]; then
    # Remove any existing miekg/dns imports to prevent duplicates/unused errors
    sed -i '/"github.com\/miekg\/dns"/d' internal/tunnel/server.go
    
    # Remove undefined handleUdpRequest usage
    sed -i '/udpHandler := http.HandlerFunc(handleUdpRequest(key))/d' internal/tunnel/server.go
    sed -i '/http.Handle("\/udp-query", limiter.Limit(udpHandler))/d' internal/tunnel/server.go
    
    # Remove duplicate handlePingRequest (it's in ping.go)
    # We delete the function definition from server.go (approximate range)
    sed -i '/func handlePingRequest(key \[\]byte) http.HandlerFunc {/,/^}/d' internal/tunnel/server.go

    # Fix pool.Get usage (replace with net.DialTimeout)
    sed -i 's/targetConn, err := pool.Get(destination)/targetConn, err := net.DialTimeout("tcp", destination, 5*time.Second)/' internal/tunnel/server.go
    
    # Fix pool.Put usage (replace with Close)
    sed -i 's/defer pool.Put(targetConn)/defer targetConn.Close()/' internal/tunnel/server.go
    
    # Fix dtls.NewListener error (replace with dtls.Listen)
    # 1. Comment out net.ListenUDP (use // instead of #)
    sed -i 's|udpConn, err := net.ListenUDP("udp", udpAddr)|// udpConn, err := net.ListenUDP("udp", udpAddr)|' internal/tunnel/server.go
    
    # 2. Replace NewListener with Listen
    # We use | as delimiter to avoid escaping /
    # We escape & as \& to prevent sed from treating it as "matched string"
    sed -i 's|dtlsListener, err := dtls.NewListener(udpConn, &dtls.Config{|dtlsListener, err := dtls.Listen("udp", udpAddr, \&dtls.Config{|' internal/tunnel/server.go
fi
# 5. Fix Unused Imports (Cleanup)
if [ -f "internal/tunnel/dns.go" ]; then
    sed -i '/^[[:space:]]*"net"$/d' internal/tunnel/dns.go
fi
if [ -f "internal/tunnel/ping.go" ]; then
    sed -i '/^[[:space:]]*"fmt"$/d' internal/tunnel/ping.go
fi
if [ -f "internal/tunnel/server.go" ]; then
    sed -i '/^[[:space:]]*"github.com\/ehsanking\/elahe-tunnel\/internal\/pool"$/d' internal/tunnel/server.go
    sed -i '/^[[:space:]]*"context"$/d' internal/tunnel/server.go
fi

# 6. Fix cmd/root.go (Syntax error due to backticks in ASCII art)
if [ -f "cmd/root.go" ]; then
    # The ASCII art contains backticks which break the Go string literal.
    # We replace the multi-line Long description with a simple string.
    # 1. Insert the new safe line before the broken block
    sed -i '/Long: `/i \	Long: "Elahe Tunnel",' cmd/root.go
    # 2. Delete the broken block (from Long: ` to `,)
    sed -i '/Long: `/,/`,/d' cmd/root.go
fi

# 7. Fix cmd/status.go (Missing cobra import, unused imports)
if [ -f "cmd/status.go" ]; then
    # Add missing cobra import
    sed -i '/import (/a \	"github.com/spf13/cobra"' cmd/status.go
    
    # Remove unused imports
    sed -i '/"crypto\/tls"/d' cmd/status.go
    sed -i '/"net\/http"/d' cmd/status.go
    sed -i '/"time"/d' cmd/status.go
    sed -i '/"github.com\/ehsanking\/elahe-tunnel\/internal\/crypto"/d' cmd/status.go
    sed -i '/"github.com\/ehsanking\/elahe-tunnel\/internal\/masquerade"/d' cmd/status.go
fi

echo -e " ${GREEN}OK${NC}"
# ---------------------------------

(
    # Use goproxy.io to bypass potential restrictions for modules
    export GOPROXY=https://goproxy.io,direct
    # Force use of local toolchain to prevent network attempts to download Go
    export GOTOOLCHAIN=local
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

# Cleanup only if we downloaded
if [ -f "../install.sh" ]; then
    cd ..
    rm -rf Elahe-Tunnel-main main.zip
fi
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
