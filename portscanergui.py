import socket
import threading
import time
import queue
import sys
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---------------------------
# Service Map (extend freely)
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}


# ---------------------------
# Scanner Worker
# ---------------------------
class PortScanner:
    """
    Scans a range of TCP ports on a target host using a thread pool.

    Args:
        target:      Resolved IP address of the host to scan.
        start_port:  First port in the scan range (inclusive).
        end_port:    Last port in the scan range (inclusive).
        timeout:     Per-port connection timeout in seconds.
        max_workers: Maximum number of concurrent threads.
    """

    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=200):
        self.target = target          # expects a pre-resolved IP
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers

        self._stop_event = threading.Event()
        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []          # list of (port, service) tuples
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        """Signal the scanner to stop after the current batch of ports."""
        self._stop_event.set()

    @staticmethod
    def resolve(hostname):
        """Resolve a hostname to an IP address. Raises socket.gaierror on failure."""
        return socket.gethostbyname(hostname)

    def _scan_port(self, port):
        """Try to connect to a single port and report the result via the queue."""
        if self._stop_event.is_set():
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    service = COMMON_PORTS.get(port, 'Unknown')
                    with self._lock:
                        self.open_ports.append((port, service))
                    self.result_queue.put(('open', port, service))
        except OSError as exc:
            self.result_queue.put(('error', port, str(exc)))
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def run(self):
        """
        Scan all ports in the range using a ThreadPoolExecutor.
        Puts ('done', None, None) on the queue when finished.
        """
        ports = [
            p for p in range(self.start_port, self.end_port + 1)
            if not self._stop_event.is_set()
        ]
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(self._scan_port, ports)

        self.result_queue.put(('done', None, None))


# ---------------------------
# Tkinter GUI
# ---------------------------
class ScannerGUI(tk.Tk):
    """Main application window for the Network Port Scanner."""

    POLL_MS = 40   # how often (ms) to drain the result queue

    def __init__(self):
        super().__init__()
        self.title("Network Port Scanner")
        self.geometry("760x580")
        self.minsize(700, 520)

        self.scanner_thread = None
        self.scanner = None
        self.start_time = None

        self._build_ui()

    # --------------------------------------------------
    # UI Construction
    # --------------------------------------------------
    def _build_ui(self):
        # ── Scan Settings ──────────────────────────────
        frm_top = ttk.LabelFrame(self, text="Scan Settings")
        frm_top.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm_top, text="Target (IP / Hostname):").grid(
            row=0, column=0, padx=8, pady=8, sticky="e")
        self.ent_target = ttk.Entry(frm_top, width=34)
        self.ent_target.grid(row=0, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm_top, text="Start Port:").grid(
            row=0, column=2, padx=8, pady=8, sticky="e")
        self.ent_start = ttk.Entry(frm_top, width=10)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        ttk.Label(frm_top, text="End Port:").grid(
            row=0, column=4, padx=8, pady=8, sticky="e")
        self.ent_end = ttk.Entry(frm_top, width=10)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=0, column=5, padx=8, pady=8, sticky="w")

        self.btn_start = ttk.Button(frm_top, text="Start Scan", command=self.start_scan)
        self.btn_start.grid(row=1, column=4, padx=8, pady=8, sticky="e")

        self.btn_stop = ttk.Button(frm_top, text="Stop", command=self.stop_scan,
                                   state="disabled")
        self.btn_stop.grid(row=1, column=5, padx=8, pady=8, sticky="w")

        for i in range(6):
            frm_top.grid_columnconfigure(i, weight=1)

        # ── Advanced Settings ──────────────────────────
        frm_adv = ttk.LabelFrame(self, text="Advanced (optional)")
        frm_adv.pack(fill="x", padx=10, pady=(0, 6))

        ttk.Label(frm_adv, text="Timeout (s):").grid(
            row=0, column=0, padx=8, pady=6, sticky="e")
        self.ent_timeout = ttk.Entry(frm_adv, width=8)
        self.ent_timeout.insert(0, "0.5")
        self.ent_timeout.grid(row=0, column=1, padx=8, pady=6, sticky="w")

        ttk.Label(frm_adv, text="Max Threads:").grid(
            row=0, column=2, padx=8, pady=6, sticky="e")
        self.ent_threads = ttk.Entry(frm_adv, width=8)
        self.ent_threads.insert(0, "200")
        self.ent_threads.grid(row=0, column=3, padx=8, pady=6, sticky="w")

        ttk.Label(frm_adv, text="(Lower timeout = faster; lower threads = gentler on network)",
                  foreground="gray").grid(row=0, column=4, columnspan=2, padx=8, sticky="w")

        # ── Status ─────────────────────────────────────
        frm_status = ttk.LabelFrame(self, text="Status")
        frm_status.pack(fill="x", padx=10, pady=(0, 10))

        self.var_status = tk.StringVar(value="Idle")
        ttk.Label(frm_status, textvariable=self.var_status).pack(
            side="left", padx=10, pady=8)

        self.var_elapsed = tk.StringVar(value="Elapsed: 0.00s")
        ttk.Label(frm_status, textvariable=self.var_elapsed).pack(
            side="right", padx=10, pady=8)

        self.progress = ttk.Progressbar(frm_status, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 10))

        # ── Results ────────────────────────────────────
        frm_results = ttk.LabelFrame(self, text="Open Ports")
        frm_results.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.txt_results = tk.Text(frm_results, height=16, wrap="none")
        self.txt_results.pack(fill="both", expand=True, side="left",
                              padx=(10, 0), pady=10)

        yscroll = ttk.Scrollbar(frm_results, orient="vertical",
                                command=self.txt_results.yview)
        yscroll.pack(side="right", fill="y", pady=10)
        self.txt_results.configure(yscrollcommand=yscroll.set)

        xscroll = ttk.Scrollbar(self, orient="horizontal",
                                command=self.txt_results.xview)
        xscroll.pack(fill="x", padx=10, pady=(0, 10))
        self.txt_results.configure(xscrollcommand=xscroll.set)

        # ── Bottom Buttons ─────────────────────────────
        frm_bottom = ttk.Frame(self)
        frm_bottom.pack(fill="x", padx=10, pady=(0, 12))

        ttk.Button(frm_bottom, text="Clear", command=self.clear_results).pack(side="left")

        self.btn_save = ttk.Button(frm_bottom, text="Save Results",
                                   command=self.save_results, state="disabled")
        self.btn_save.pack(side="right")

    # --------------------------------------------------
    # Scan Control
    # --------------------------------------------------
    def start_scan(self):
        """Validate inputs, resolve target, then kick off the scanner thread."""
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("Scanner", "A scan is already running.")
            return

        # ── Validate basic inputs ──
        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        try:
            start_port = int(self.ent_start.get().strip())
            end_port = int(self.ent_end.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be integers.")
            return

        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535
                and start_port <= end_port):
            messagebox.showerror(
                "Input Error",
                "Port range must be within 0–65535 and start ≤ end.")
            return

        # ── Validate advanced inputs ──
        try:
            timeout = float(self.ent_timeout.get().strip())
            max_threads = int(self.ent_threads.get().strip())
            if timeout <= 0 or max_threads < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "Input Error",
                "Timeout must be a positive number; threads must be a positive integer.")
            return

        # ── Resolve hostname → IP (cache result in scanner.target) ──
        try:
            resolved_ip = PortScanner.resolve(target)
        except socket.gaierror as exc:
            messagebox.showerror(
                "Resolution Error",
                f"Failed to resolve '{target}'.\n{exc}")
            return

        # ── Build scanner with the resolved IP, not the raw hostname ──
        self.scanner = PortScanner(
            target=resolved_ip,       # pre-resolved: no repeated DNS lookups
            start_port=start_port,
            end_port=end_port,
            timeout=timeout,
            max_workers=max_threads,
        )

        self.append_text(f"Target : {target} ({resolved_ip})\n")
        self.append_text(f"Range  : {start_port}–{end_port}  |  "
                         f"Timeout: {timeout}s  |  Threads: {max_threads}\n\n")

        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_save.configure(state="disabled")
        self._reset_progress()
        self.start_time = time.time()
        self.var_status.set("Scanning...")
        self._update_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()
        self.after(self.POLL_MS, self._poll_results)

    def stop_scan(self):
        """Ask the scanner to stop gracefully."""
        if self.scanner:
            self.scanner.stop()
            self.var_status.set("Stopping…")

    # --------------------------------------------------
    # Result Polling
    # --------------------------------------------------
    def _poll_results(self):
        """Drain the result queue and update the UI. Re-schedules itself until done."""
        if not self.scanner:
            return

        try:
            while True:
                msg_type, a, b = self.scanner.result_queue.get_nowait()

                if msg_type == 'open':
                    port, service = a, b
                    self.append_text(f"[+] Port {port:>5}  ({service})\n")

                elif msg_type == 'error':
                    port, reason = a, b
                    # Only surface errors that aren't plain "connection refused"
                    if 'refused' not in reason.lower() and 'timed out' not in reason.lower():
                        self.append_text(f"[!] Port {port:>5}  error: {reason}\n")

                elif msg_type == 'progress':
                    scanned, total = a, b
                    self.progress.configure(maximum=max(total, 1), value=scanned)
                    self.var_status.set(f"Scanning… {scanned}/{total}")

                elif msg_type == 'done':
                    self._on_scan_done()
                    return   # stop polling

        except queue.Empty:
            pass

        # Still running — reschedule
        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.POLL_MS, self._poll_results)
        else:
            self._on_scan_done()

    def _on_scan_done(self):
        """Called once the scan finishes (naturally or via Stop)."""
        total_open = len(self.scanner.open_ports) if self.scanner else 0
        self.append_text(f"\nScan complete — {total_open} open port(s) found.\n")
        self.var_status.set("Completed")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_save.configure(state="normal" if total_open else "disabled")
        self.start_time = None

    # --------------------------------------------------
    # UI Helpers
    # --------------------------------------------------
    def append_text(self, text):
        self.txt_results.insert(tk.END, text)
        self.txt_results.see(tk.END)

    def _reset_progress(self):
        self.progress.configure(value=0, maximum=1)

    def _update_elapsed(self):
        if self.start_time and self.var_status.get() in ("Scanning…", "Stopping…"):
            elapsed = time.time() - self.start_time
            self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s")
            self.after(200, self._update_elapsed)

    def clear_results(self):
        self.txt_results.delete("1.0", tk.END)
        self._reset_progress()
        self.var_status.set("Idle")
        self.var_elapsed.set("Elapsed: 0.00s")
        self.btn_save.configure(state="disabled")

    def save_results(self):
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Save Results", "No open ports to save.")
            return

        default_name = f"open_ports_{int(time.time())}.txt"
        file_path = filedialog.asksaveasfilename(
            title="Save results",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("Open Ports\n")
                f.write("=" * 30 + "\n")
                for port, service in sorted(self.scanner.open_ports, key=lambda x: x[0]):
                    f.write(f"Port {port:<6} {service}\n")
            messagebox.showinfo("Saved", f"Results saved to:\n{file_path}")
        except OSError as exc:
            messagebox.showerror("Save Error", f"Failed to save file.\n{exc}")


# ---------------------------
# Entry Point
# ---------------------------
def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
