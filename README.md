# 🔍 Network Port Scanner

> A lightweight TCP port scanner with a clean GUI — built with Python and Tkinter.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

Enter a target host and port range — the scanner checks each port concurrently using a **thread pool** and identifies open services in real time through a graphical interface.

---

## Features

| Feature | Details |
|---|---|
| 🖥️ Simple interface | 3-field input: target host, start port, end port |
| ⚡ Fast scanning | `ThreadPoolExecutor` with configurable thread count |
| ⚙️ Advanced controls | Timeout and max threads exposed in the UI |
| 🏷️ Service labels | Auto-identifies FTP, SSH, HTTP, MySQL, RDP, and more |
| 📊 Live progress | Progress bar + elapsed timer update in real time |
| ⛔ Graceful stop | Cancel a scan at any point |
| 💾 Export results | Save open ports to a `.txt` file |
| 🌐 Cross-platform | Runs on Windows, macOS, and Linux |

---

## Requirements

- Python **3.7+**
- `tkinter` — ships with standard Python; on Debian/Ubuntu run:
  ```bash
  sudo apt install python3-tk
  ```

No third-party packages required.

---

## Installation

```bash
git clone https://github.com/Jagadeshmatta/Networkscan.git
cd Networkscan
```

---

## Usage

```bash
python portscanergui.py
```

1. Enter the **Target** — IP address (e.g. `192.168.1.1`) or hostname (e.g. `scanme.nmap.org`)
2. Set **Start Port** and **End Port** (defaults: `1` – `1024`)
3. Optionally adjust **Timeout** and **Max Threads** in the Advanced panel
4. Click **Start Scan** — open ports appear live in the results pane
5. Click **Stop** to cancel early
6. Click **Save Results** to export to a `.txt` file

---

## Detected Services

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 3306 | MySQL |
| 23 | Telnet | 3389 | RDP |
| 25 | SMTP | 5900 | VNC |
| 53 | DNS | 8080 | HTTP-Alt |
| 80 | HTTP | 110 | POP3 |
| 143 | IMAP | — | — |

> Ports not in this list are reported as `Unknown`.

---

## Advanced Settings

Exposed directly in the UI — no code editing needed:

| Setting | Description | Default |
|---|---|---|
| **Timeout (s)** | Per-port connection timeout. Lower = faster, but may miss ports on slow networks | `0.5` |
| **Max Threads** | Concurrent thread count. Lower = gentler on the network | `200` |

---

## Project Structure

```
Networkscan/
├── portscanergui.py   # Scanner logic + GUI
└── README.md
```

---

## ⚠️ Disclaimer

Use this tool **only on hosts and networks you own or have explicit permission to scan**.  
Unauthorized port scanning may be illegal in your jurisdiction.

---

## License

Released under the [MIT License](https://opensource.org/licenses/MIT).
