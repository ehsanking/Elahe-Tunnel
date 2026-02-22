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

# 1. Check for Go
MIN_GO_VERSION="1.24.0"

version_ge() { test "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2"; }

if command_exists go; then
    GO_VERSION=$(go version | { read -r _ _ v _; echo "${v#go}"; })
    if version_ge "$GO_VERSION" "$MIN_GO_VERSION"; then
        echo "✅ Go compiler version $GO_VERSION is installed and meets the requirement (>= $MIN_GO_VERSION)."
    else
        echo "❌ Installed Go version ($GO_VERSION) is too old. Please upgrade to Go $MIN_GO_VERSION or newer."
        exit 1
    fi
else
    echo "Go compiler not found. Attempting to install for Debian/Ubuntu..."
    if command_exists apt-get; then
        if [ "$(id -u)" -ne 0 ]; then
            echo "This script needs to run as root or with sudo to install Go."
            echo "Please run again with sudo: sudo $0"
            exit 1
        fi
        apt-get update
        apt-get install -y golang-go
        echo "✅ Go compiler has been installed."
    else
        echo "❌ Could not find 'apt-get'. Please install the Go compiler (version 1.24+) manually and re-run this script."
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
