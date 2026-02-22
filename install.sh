#!/bin/bash
#
# Installation script for Elahe Tunnel
#
# This script checks for the Go compiler. If it's not found, it attempts to
# install it using apt-get for Debian/Ubuntu-based systems. Finally, it
# compiles and installs the Elahe Tunnel binary.

set -e # Exit immediately if a command exits with a non-zero status.

# --- Helper Functions ---
command_exists() {
    command -v "$@" >/dev/null 2>&1
}

# --- Main Logic ---
echo "Starting Elahe Tunnel installation..."

# 1. Check for Go and offer upgrade
MIN_GO_VERSION="1.24.0"
NEEDS_INSTALL_OR_UPGRADE=false

version_ge() { test "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2"; }

if command_exists go; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if version_ge "$GO_VERSION" "$MIN_GO_VERSION"; then
        echo "✅ Go compiler version $GO_VERSION is installed and meets the requirement (>= $MIN_GO_VERSION)."
    else
        echo "⚠️ Your installed Go version ($GO_VERSION) is too old. Elahe Tunnel requires Go $MIN_GO_VERSION or newer."
        NEEDS_INSTALL_OR_UPGRADE=true
    fi
else
    echo "Go compiler not found."
    NEEDS_INSTALL_OR_UPGRADE=true
fi

if [ "$NEEDS_INSTALL_OR_UPGRADE" = true ]; then
    read -p "Would you like this script to attempt to download and install the latest version of Go? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Downloading and installing the latest Go version..."
        if [ "$(id -u)" -ne 0 ]; then
            echo "This script needs root/sudo privileges to install Go to /usr/local. Please run with sudo."
            exit 1
        fi
        
        CURL_OPTS="-s -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36' --referer 'https://go.dev/'"
        
        GO_LATEST_VERSION=$(curl $CURL_OPTS "https://go.dev/VERSION?m=text" | awk '/^go/ {print $1; exit}' | tr -d '\r')
        ARCH=$(uname -m)
        case $ARCH in
            "x86_64") ARCH="amd64" ;;
            "aarch64") ARCH="arm64" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        
        DOWNLOAD_URL="https://storage.googleapis.com/golang/${GO_LATEST_VERSION}.linux-${ARCH}.tar.gz"
        echo "Downloading from $DOWNLOAD_URL"
        curl $CURL_OPTS -L -o /tmp/go.tar.gz "$DOWNLOAD_URL"

        if ! file /tmp/go.tar.gz | grep -q 'gzip compressed data'; then
            echo "❌ Download failed. The downloaded file is not a valid gzip archive."
            echo "This often happens due to network filtering or regional blocks preventing access to go.dev."
            echo "Please try running the script again, or download the archive manually and place it at /tmp/go.tar.gz before running."
            exit 1
        fi

        echo "Extracting Go archive..."
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
        
        export PATH=$PATH:/usr/local/go/bin
        echo "✅ Go has been installed to version $(go version | awk '{print $3}')."
    else
        echo "Installation aborted. Please install Go $MIN_GO_VERSION or newer manually and re-run this script."
        exit 1
    fi
fi

# 2. Setup Go environment
# This ensures the 'go' command and its bin directory are available in the current script session.
if [ -d "/usr/local/go/bin" ]; then
    export PATH=$PATH:/usr/local/go/bin
fi
if command_exists go; then
    export PATH=$PATH:$(go env GOPATH)/bin
fi

# 3. Install Elahe Tunnel
echo "Compiling and installing Elahe Tunnel... (This may take a moment depending on your network)"
go install github.com/ehsanking/elahe-tunnel@latest

# 3. Interactive Setup
echo ""
echo "Elahe Tunnel is installed. Now let's configure it."
PS3='Select the mode for this server: '
options=("Internal (inside a censored network, e.g., Iran)" "External (with unrestricted internet, e.g., Germany)" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Internal (inside a censored network, e.g., Iran)")
            echo "Configuring as an internal server..."
            elahe-tunnel setup internal
            break
            ;;
        "External (with unrestricted internet, e.g., Germany)")
            echo "Configuring as an external server..."
            elahe-tunnel setup external
            break
            ;;
        "Quit")
            break
            ;;
        *)
            echo "Invalid option $REPLY"
            ;;
    esac
done

# 4. Post-installation instructions

echo ""
echo "✅ Elahe Tunnel has been compiled and installed!"
echo ""
echo "--- IMPORTANT NEXT STEPS ---"
echo "To use the 'elahe-tunnel' command, you need to add Go's binary path to your shell's PATH variable."
echo "1. Find your Go binary path by running: go env GOPATH"
echo "2. Open your shell configuration file (e.g., ~/.bashrc, ~/.zshrc)."
echo "3. Add the following line to the end of the file (replace '~/go' if your path is different):"
echo "   export PATH=\"$PATH:$(go env GOPATH)/bin\""
echo "4. Save the file and restart your terminal, or run 'source ~/.bashrc' (or your respective config file)."
echo ""
echo "After these steps, the 'elahe-tunnel run' command will be available."
