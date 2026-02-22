# Elahe Tunnel

> A censorship circumvention tool that disguises network traffic as Google search packets.

[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.0.1-orange.svg)](/VERSION)

**Elahe Tunnel** is an experimental tool designed to bypass sophisticated Deep Packet Inspection (DPI) systems by camouflaging data packets to look like legitimate Google search queries and results. It's built for scenarios where internet access is heavily restricted or monitored.

## 💡 How It Works

The core idea is to create a tunnel between two servers: an **internal node** (inside the censored network, e.g., Iran) and an **external node** (with unrestricted internet access, e.g., Germany).

1.  **External Node (Exit Point):** This server waits for incoming connections. When it receives a packet that looks like a Google search, it extracts the hidden data, forwards it to the public internet, gets the response, and then wraps that response inside a fake Google search results HTML page to send back.

2.  **Internal Node (Relay):** This server takes TCP traffic from a local user, encrypts it, and wraps it into a packet that mimics a Google search query. It then sends this to the external node.

This masquerading technique aims to make the traffic pattern indistinguishable from regular web browsing, thus evading detection by automated censorship systems.

## 🚀 Getting Started

### Installation Guide

Due to potential network restrictions that can interfere with direct installation on servers, the recommended method is to compile the application on your local machine and then transfer the binary to your server.

**Step 1: On Your Local Machine (with Go 1.24+ installed)**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ehsanking/elahe-tunnel.git
    cd elahe-tunnel
    ```

2.  **Run the build script:**
    This script will compile the application for a standard Linux server (amd64 architecture).
    ```bash
    bash build.sh
    ```

3.  **Transfer the binary to your server:**
    After a successful build, a binary file named `elahe-tunnel` will be created in a `release` directory. Use `scp` or any other file transfer method to upload it to your server.
    ```bash
    # Replace user@your_server_ip with your server's details
    scp release/elahe-tunnel user@your_server_ip:~
    ```

**Step 2: On Your Server**

1.  **Make the binary executable:**
    ```bash
    chmod +x ~/elahe-tunnel
    ```

2.  **Run the interactive setup:**
    The application will guide you through configuring it as an internal or external server.
    ```bash
    ./elahe-tunnel setup
    ```

### Usage

Once installed and configured, you can start the tunnel with:

```bash
elahe-tunnel run
```

#### Step 3: Check the Tunnel Status

You can check the status of the connection at any time on either server.

```bash
elahe-tunnel status
```

**Example Output:**
```
Checking tunnel status...
Status: Active
```

## Commands

- `elahe-tunnel setup [internal | external]`: Configure the server node.
- `elahe-tunnel status`: Check the tunnel's connection status.
- `elahe-tunnel version`: Show the current version of the tool.

## 🤝 Contributing

This project is in its early stages (v0.0.1), and contributions are highly welcome. Feel free to open an issue to report bugs, suggest features, or submit a pull request.

Special thanks to **EhsanKing** for the original idea and technical analysis.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
