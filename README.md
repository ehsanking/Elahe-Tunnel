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

### Installation

**Requirement:** You need Go version **1.24.0** or newer.

Run the following command in your terminal. This script will check your Go version, guide you through the installation, and then configure the tunnel interactively.

```bash
bash <(curl -s -L https://raw.githubusercontent.com/ehsanking/elahe-tunnel/main/install.sh)
```

After the script finishes, you **must** add the Go binary path to your shell's configuration to use the `elahe-tunnel` command. The script will provide you with the exact instructions.

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
