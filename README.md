<div align="center">
  <img src="https://images.unsplash.com/photo-1558494949-efc52728101c?q=80&w=2000&auto=format&fit=crop" alt="Elahe Tunnel Header" width="100%" style="border-radius: 10px; max-height: 300px; object-fit: cover;">

  <h1 style="margin-top: 20px;">Elahe Tunnel</h1>
  <p><strong>Next-Gen Censorship Circumvention & Traffic Obfuscation</strong></p>

  <p>
    <a href="https://golang.org/"><img src="https://img.shields.io/badge/Made%20with-Go-00ADD8?style=for-the-badge&logo=go" alt="Made with Go"></a>
    <a href="/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"></a>
    <a href="#"><img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" alt="Platform"></a>
    <a href="#"><img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status"></a>
  </p>
</div>

---

## 🚀 Overview

**Elahe Tunnel** is an advanced, high-performance tunneling tool engineered to bypass sophisticated Deep Packet Inspection (DPI) systems. By camouflaging data packets to mimic legitimate Google Search queries and results, it renders traffic indistinguishable from normal web browsing.

Designed for resilience in restrictive network environments, it provides a secure, encrypted bridge between an internal node (e.g., inside a censored region) and an external node (with unrestricted internet access).

## ✨ Key Features

*   **🕵️ Advanced Obfuscation:** Encapsulates traffic within HTTP GET/POST requests that perfectly mimic Google Search patterns, fooling heuristic analysis.
*   **🔒 Military-Grade Encryption:** All data is secured with **AES-256-GCM** encryption, ensuring confidentiality and integrity.
*   **⚡ High Performance:** Built with Go for superior concurrency, low latency, and minimal resource footprint.
*   **📊 Real-Time Web Dashboard:** Monitor traffic, active connections, and system health via a modern, responsive web interface.
*   **🌐 Multi-Protocol Support:**
    *   **TCP:** Robust tunneling for standard web traffic.
    *   **UDP (DTLS):** Secure, low-latency transport for voice/video calls and gaming.
    *   **DNS:** Encrypted DNS proxy to prevent DNS poisoning and leakage.
*   **🛠️ Easy Deployment:** Single-command installation and interactive setup wizard.

## 🛠️ Architecture

The system operates on a client-server model:

1.  **Internal Node (Client):** Located within the restricted network. It accepts local traffic, encrypts it, wraps it in a fake Google Search query, and sends it to the external node.
2.  **External Node (Server):** Located in an unrestricted network. It receives the "search query," unwraps and decrypts the payload, forwards it to the destination, and returns the response wrapped in a fake Google Search results page.

```mermaid
graph LR
    User[User Device] -->|TCP/UDP| Client[Internal Node]
    Client -->|Fake Google Search (Encrypted)| Server[External Node]
    Server -->|Real Traffic| Internet[Internet]
    Internet -->|Response| Server
    Server -->|Fake Search Result (Encrypted)| Client
    Client -->|Decrypted Data| User
```

## 📦 Installation

Install and configure Elahe Tunnel with a single command. This script handles dependencies (Go) and setup automatically.

```bash
bash <(curl -s -L https://raw.githubusercontent.com/ehsanking/elahe-tunnel/main/install.sh)
```

## 🚦 Usage

Once installed, manage the tunnel using the `elahe-tunnel` CLI:

### 1. Setup
Configure your node as either **Internal** (Client) or **External** (Server).
```bash
elahe-tunnel setup
```

### 2. Run
Start the tunnel service.
```bash
elahe-tunnel run
```

### 3. Monitor
Access the web dashboard at `http://YOUR_IP:8080` (default port) to view real-time statistics.
Login with the credentials set during setup.

## 🔧 Configuration

Configuration is stored in `search_tunnel_config.json`. You can modify it manually or use the `setup` command.

| Key | Description |
| :--- | :--- |
| `node_type` | `internal` or `external` |
| `remote_host` | IP/Domain of the external server |
| `connection_key` | Base64 encoded AES-256 key (must match on both nodes) |
| `web_panel_enabled` | Enable/Disable the web dashboard |
| `web_panel_port` | Port for the web dashboard |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1.  Fork the repository
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

---
<div align="center">
  <sub>Built with ❤️ for internet freedom.</sub>
</div>
