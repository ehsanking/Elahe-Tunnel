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
if command_exists go; then
    echo "✅ Go compiler is already installed."
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
        echo "❌ Could not find 'apt-get'. Please install the Go compiler (version 1.22+) manually and re-run this script."
        exit 1
    fi
fi

# 2. Install Elahe Tunnel
echo "Compiling and installing Elahe Tunnel..."
go install github.com/ehsanking/search-tunnel@latest

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
echo "✅ Elahe Tunnel installation and setup complete!"
echo ""
echo "You can now run the tunnel using the 'elahe-tunnel run' command."
