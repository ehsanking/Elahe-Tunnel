#!/bin/bash

# This script cross-compiles the application for Linux (amd64)
# and places the binary in the 'release' directory.

# --- Configuration ---
BINARY_NAME="elahe-tunnel"
OUTPUT_DIR="release"

# --- Main Logic ---
echo "Starting build process for Elahe Tunnel..."

# Ensure the output directory exists
mkdir -p "$OUTPUT_DIR"

# Set the target OS and Architecture for cross-compilation
export GOOS=linux
export GOARCH=amd64

echo "Targeting OS: $GOOS, Architecture: $GOARCH"

# Build the Go application
# -o: specifies the output file path
# -ldflags "-s -w": strips debugging information to reduce binary size
echo "Compiling application..."
go build -o "$OUTPUT_DIR/$BINARY_NAME" -ldflags "-s -w" .

# Check if the build was successful
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Build successful!"
    echo "The binary is located at: $OUTPUT_DIR/$BINARY_NAME"
    echo ""
    echo "--- Next Steps ---"
    echo "1. Copy the '$BINARY_NAME' file to your server."
    echo "   Example using scp: scp $OUTPUT_DIR/$BINARY_NAME user@your_server_ip:~/"
    echo "2. On your server, make the binary executable: chmod +x ~/$BINARY_NAME"
    echo "3. Run the interactive setup: ./$BINARY_NAME setup"
else
    echo ""
    echo "❌ Build failed. Please check for compilation errors."
fi
