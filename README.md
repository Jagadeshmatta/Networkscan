Network Port Scanner
GUI Tool  |  Python + Tkinter  |  MIT License
Overview
A lightweight TCP port scanner with a graphical interface. Enter a target host and port range — the scanner checks each port concurrently and identifies open services in real time.

Features
•	Target host, start port, end port — Simple 3-field interface
•	Efficient concurrent scanning with configurable thread count — ThreadPoolExecutor scanning
•	Exposed in the Advanced panel — Configurable timeout and threads
•	Auto-labels well-known ports (FTP, SSH, HTTP, MySQL, RDP, etc.) — Service identification
•	Progress bar and elapsed-time counter update live — Real-time progress
•	Cancel a running scan gracefully — Stop at any time
•	Export discovered open ports to a .txt file — Save results
•	Runs on Windows, macOS, and Linux — Cross-platform

Requirements
•	Python 3.7 or newer
•	Tkinter — included in standard Python; on Debian/Ubuntu install python3-tk
No third-party packages required.

Installation
git clone https://github.com/Jagadeshmatta/Networkscan.git
cd Networkscan

Usage
python portscanergui.py

1. Enter the Target — an IP address or hostname (e.g. 192.168.1.1 or scanme.nmap.org).
2. Set the Start Port and End Port (defaults: 1 – 1024).
3. Optionally adjust Timeout and Max Threads in the Advanced panel.
4. Click Start Scan. Open ports appear in real time in the results pane.
5. Click Stop to cancel early.
6. Click Save Results to export the open-port list to a text file.

Detected Services
The following ports are automatically labelled:

Port	Service
21	FTP
22	SSH
23	Telnet
25	SMTP
53	DNS
80	HTTP
110	POP3
143	IMAP
443	HTTPS
3306	MySQL
3389	RDP
5900	VNC
8080	HTTP-Alt
Ports not in the list are reported as Unknown.

Project Structure
Networkscan/
├── portscanergui.py   # Scanner logic + GUI
└── README.md

Advanced Settings
Exposed in the UI — no code editing needed:
•	Timeout (s) — per-port connection timeout. Lower = faster scan, more missed ports on slow networks. Default: 0.5s
•	Max Threads — concurrent thread count. Lower = gentler on the network. Default: 200

Disclaimer
Use this tool only on hosts and networks you own or have explicit permission to scan. Unauthorized port scanning may be illegal in your jurisdiction.

License
Released under the MIT License.
