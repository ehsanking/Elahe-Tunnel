# Search Tunnel

> A censorship circumvention tool that disguises network traffic as Google search packets.

[![Go Version](https://img.shields.io/badge/go-1.22-blue.svg)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.0.1-orange.svg)](/VERSION)

**Search Tunnel** is an experimental tool designed to bypass sophisticated Deep Packet Inspection (DPI) systems by camouflaging data packets to look like legitimate Google search queries and results. It's built for scenarios where internet access is heavily restricted or monitored.

## 💡 How It Works

The core idea is to create a tunnel between two servers: an **internal node** (inside the censored network, e.g., Iran) and an **external node** (with unrestricted internet access, e.g., Germany).

1.  **External Node (Exit Point):** This server waits for incoming connections. When it receives a packet that looks like a Google search, it extracts the hidden data, forwards it to the public internet, gets the response, and then wraps that response inside a fake Google search results HTML page to send back.

2.  **Internal Node (Relay):** This server takes TCP traffic from a local user, encrypts it, and wraps it into a packet that mimics a Google search query. It then sends this to the external node.

This masquerading technique aims to make the traffic pattern indistinguishable from regular web browsing, thus evading detection by automated censorship systems.

## 🚀 Getting Started

### Installation

To install the `search-tunnel` CLI, you need to have Go (version 1.22+) installed on your system.

Run the following command in your terminal:

```bash
# This will download, compile, and install the binary to your GOPATH
go install github.com/ehsanking/search-tunnel@latest
```

Alternatively, you can download a pre-compiled binary for your operating system from the [GitHub Releases](https://github.com/ehsanking/search-tunnel/releases) page (once available).

### Usage

The setup process involves configuring the external server first, then the internal one.

#### Step 1: On Your External Server (e.g., in Germany)

Run the `setup` command in `external` mode. This will generate a secure connection key that you'll need for the internal server.

```bash
search-tunnel setup external
```

**Example Output:**
```
Setting up as an external (foreign) server...
✅ External server setup complete.

🔑 Your connection key is:

    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Save this key. You will need it to connect your internal server.
```

> **Security Note:** Keep this key private. Anyone with this key can use your tunnel.

#### Step 2: On Your Internal Server (e.g., in Iran)

Run the `setup` command in `internal` mode. The tool will prompt you to enter the IP address of your external server and the connection key you generated in the previous step.

```bash
search-tunnel setup internal
```

**Example Interaction:**
```
Setting up as an internal (Iran) server...
Enter the IP address of your external server: 123.45.67.89
Enter the connection key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

✅ Internal server setup complete. The tunnel is now attempting to connect.
```

#### Step 3: Check the Tunnel Status

You can check the status of the connection at any time on either server.

```bash
search-tunnel status
```

**Example Output:**
```
Checking tunnel status...
Status: Active
```

## Commands

- `search-tunnel setup [internal | external]`: Configure the server node.
- `search-tunnel status`: Check the tunnel's connection status.
- `search-tunnel version`: Show the current version of the tool.

## 🤝 Contributing

This project is in its early stages (v0.0.1), and contributions are highly welcome. Feel free to open an issue to report bugs, suggest features, or submit a pull request.

Special thanks to **EhsanKing** for the original idea and technical analysis.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
