import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
from concurrent.futures import ThreadPoolExecutor
import queue
import ipaddress
import time

# This dictionary contains common ports and their service names.
COMMON_PORTS = {
    # FTP, SSH, Telnet
    21: 'ftp', 22: 'ssh', 23: 'telnet',
    # Email
    25: 'smtp', 110: 'pop3', 143: 'imap',
    # DNS, DHCP, and Web
    53: 'dns', 67: 'dhcp', 68: 'dhcp-client', 80: 'http', 443: 'https',
    # Windows & Remote Access
    139: 'netbios', 445: 'smb', 3389: 'rdp', 5900: 'vnc',
    # Databases & Media
    3306: 'mysql', 5432: 'postgresql', 554: 'rtsp',
    # Alternative Web
    8080: 'http-alt', 8443: 'https-alt'
}

class ReconToolGUI(tk.Tk):
    """
    Main application class for the Network Reconnaissance Tool.
    This class handles the GUI layout, user interactions, and threading for the scanning logic.
    """
    def __init__(self):
        super().__init__()

        # --- Main Window Configuration ---
        self.title("Ghostface Security: Reconnaissance Tool")
        self.geometry("850x650")
        self.resizable(True, True)
        self.style = ttk.Style(self)
        self.style.theme_use('default')

        # Custom light theme styles
        self.configure(bg="#f0f0f0")  # Lighter background
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", foreground="#333333", font=("Segoe UI", 11))
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#007bff") # Muted blue accent
        self.style.configure("TButton", background="#007bff", foreground="#ffffff", font=("Segoe UI", 10, "bold"))
        self.style.map("TButton", background=[('active', '#0056b3')])
        self.style.configure("TEntry", fieldbackground="#ffffff", foreground="#333333", insertcolor="#333333")
        self.style.configure("TNotebook", background="#f0f0f0")
        self.style.configure("TNotebook.Tab", background="#e8e8e8", foreground="#333333", font=("Segoe UI", 10))
        self.style.map("TNotebook.Tab", background=[('selected', '#007bff')], foreground=[('selected', '#ffffff')])
        self.style.configure("TProgressbar", thickness=15, troughcolor="#e0e0e0", background="#007bff")
        
        # --- Shared Data Structures ---
        self.network_scan_results = {}
        self.scan_lock = threading.Lock()
        self.log_queue = queue.Queue()
        
        # --- Create Widgets ---
        self.main_frame = ttk.Frame(self, padding="20")
        self.main_frame.pack(fill="both", expand=True)

        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=5)
        self.main_frame.columnconfigure(2, weight=1)
        self.main_frame.rowconfigure(3, weight=1)

        self.header_label = ttk.Label(self.main_frame, text="Network Reconnaissance Tool", style="Header.TLabel")
        self.header_label.grid(row=0, column=1, pady=(0, 20))

        self.input_frame = ttk.Frame(self.main_frame, padding="10", style="TFrame")
        self.input_frame.grid(row=1, column=1, sticky="ew", pady=(0, 10))
        self.input_frame.columnconfigure(1, weight=1)

        ttk.Label(self.input_frame, text="Target IP/Range:", font=('Segoe UI', 11, 'bold')).grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        self.input_entry = ttk.Entry(self.input_frame, width=40)
        self.input_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.input_entry.insert(0, '192.168.1.1/24')
        
        self.scan_options_frame = ttk.Frame(self.input_frame, padding="5", style="TFrame")
        self.scan_options_frame.grid(row=1, column=0, columnspan=2, pady=5, sticky="w")

        ttk.Label(self.scan_options_frame, text="Scan Type:").pack(side="left", padx=(0, 10))
        self.scan_type = tk.StringVar(value="full")
        self.full_scan_radio = ttk.Radiobutton(
            self.scan_options_frame, text="Full Network Scan", variable=self.scan_type, value="full",
            command=self.on_scan_type_change
        )
        self.full_scan_radio.pack(side="left", padx=(0, 10))

        self.single_host_radio = ttk.Radiobutton(
            self.scan_options_frame, text="Single Host Scan", variable=self.scan_type, value="single",
            command=self.on_scan_type_change
        )
        self.single_host_radio.pack(side="left", padx=(0, 20))
        
        ttk.Label(self.scan_options_frame, text="Specific Port:").pack(side="left", padx=(0, 5))
        self.port_entry = ttk.Entry(self.scan_options_frame, width=5)
        self.port_entry.pack(side="left")
        self.port_entry.insert(0, '80')
        self.port_entry.config(state='disabled')
        
        self.scan_button = ttk.Button(self.input_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=2, column=0, columnspan=2, pady=(10, 0))

        self.progress_bar = ttk.Progressbar(self.main_frame, orient='horizontal', mode='indeterminate', style="TProgressbar")
        self.progress_bar.grid(row=2, column=1, sticky='ew', pady=10)

        self.output_frame = ttk.Frame(self.main_frame, padding="10", style="TFrame")
        self.output_frame.grid(row=3, column=1, sticky="nsew")
        self.output_frame.columnconfigure(0, weight=1)
        self.output_frame.rowconfigure(0, weight=1)

        self.output_text = scrolledtext.ScrolledText(self.output_frame, state='disabled', wrap='word', bg="#ffffff", fg="#333333", insertbackground="#333333", borderwidth=0, relief="flat", font=("Consolas", 10))
        self.output_text.grid(row=0, column=0, sticky="nsew")

        self.status_bar = ttk.Label(self, text="Ready to perform a scan.", relief="sunken", anchor="w", background="#f0f0f0", foreground="#333333")
        self.status_bar.pack(fill="x", side="bottom")

        self.after(100, self.process_queue)

    def process_queue(self):
        """
        Processes messages from the logging queue to update the GUI thread-safely.
        """
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.output_text.config(state='normal')
                self.output_text.insert(tk.END, message + '\n')
                self.output_text.see(tk.END)
                self.output_text.config(state='disabled')
                self.log_queue.task_done()
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def on_scan_type_change(self):
        """
        Enables/disables the specific port entry based on the selected scan type.
        """
        if self.scan_type.get() == "single":
            self.port_entry.config(state='disabled')
        else:
            self.port_entry.config(state='normal')

    def log(self, message):
        """
        Adds a message to a thread-safe queue to be processed by the GUI thread.
        """
        self.log_queue.put(message)

    def start_scan(self):
        """
        Handles the button click event and starts the scanning process in a new thread.
        This prevents the GUI from freezing during a long-running scan.
        """
        target = self.input_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a valid IP address or network range.")
            return

        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.config(state='disabled')
        self.status_bar.config(text="Scanning... Please wait.")
        self.scan_button.config(state='disabled')
        self.progress_bar.start()
        
        scan_thread = threading.Thread(target=self.run_scan_logic, args=(target,))
        scan_thread.daemon = True
        scan_thread.start()

    def run_scan_logic(self, target):
        """
        This function contains the core scanning logic and runs in a separate thread.
        It calls the appropriate scanning function based on user input.
        """
        self.network_scan_results.clear()
        scan_type = self.scan_type.get()
        
        try:
            if scan_type == "single":
                self.scan_single_host_logic(target)
            else:
                port_to_check_str = self.port_entry.get().strip()
                if port_to_check_str:
                    port_to_check = int(port_to_check_str)
                    self.scan_specific_port_on_network_logic(target, port_to_check)
                else:
                    self.full_scan_on_network_logic(target)
        except Exception as e:
            self.log(f"[!] An error occurred: {e}")
        finally:
            self.after(0, self.finish_scan)

    def finish_scan(self):
        """
        Updates the GUI when the scanning thread is complete.
        """
        self.status_bar.config(text="Scan complete.")
        self.scan_button.config(state='normal')
        self.progress_bar.stop()

    def get_live_hosts(self, ip_range):
        """
        Discovers live hosts by attempting a connection to a known port.
        """
        self.log(f"[*] Discovering live hosts in {ip_range}...")
        live_hosts = []
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            with ThreadPoolExecutor(max_workers=100) as executor:
                # Use a common port like 80 for a quick "ping" to see if the host is up.
                futures = {executor.submit(self.is_host_live, str(ip)): str(ip) for ip in network.hosts()}
                for future in futures:
                    ip = futures[future]
                    if future.result():
                        live_hosts.append(ip)
                        self.log(f"    - Found live host: {ip}")
        except ValueError as e:
            self.log(f"[!] Invalid IP address or range: {e}")
            return []
        
        self.log(f"[*] Host discovery complete. Found {len(live_hosts)} live hosts.")
        return live_hosts

    def is_host_live(self, host):
        """
        Checks if a host is live by attempting to connect to a common port.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5) # Short timeout for speed
            try:
                sock.connect((host, 80)) # Try to connect to port 80 (HTTP)
                return True
            except (socket.timeout, ConnectionRefusedError, OSError):
                return False

    def scan_port_logic(self, host, port, service_name):
        """
        Worker function to scan a single port on a given host.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            try:
                sock.connect((host, port))
                with self.scan_lock:
                    if host not in self.network_scan_results:
                        self.network_scan_results[host] = []
                    self.network_scan_results[host].append(port)
                    self.log(f"[{host}] Port {port} is open ({service_name}).")
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

    def scan_single_host_logic(self, host):
        """
        Orchestrates the port scanning for a single host.
        """
        self.log(f"[*] Starting multithreaded scan on target: {host}...\n")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.scan_port_logic, host, port, service) 
                       for port, service in COMMON_PORTS.items()]
            for future in futures:
                future.result()
        
        if host in self.network_scan_results and self.network_scan_results[host]:
            self.log(f"\n[+] Scan complete for {host}. Found {len(self.network_scan_results[host])} open ports.")
        else:
            self.log(f"\nNo open ports found on {host}.")
        
    def full_scan_on_network_logic(self, ip_range):
        """
        Performs a network scan and then a full port scan on all live hosts.
        """
        live_hosts = self.get_live_hosts(ip_range)
        if not live_hosts:
            self.log("[!] No live hosts found. Exiting.")
            return

        self.log("\n" + "="*50)
        self.log("Starting full port scan on all live hosts...")
        self.log("="*50 + "\n")

        for host in live_hosts:
            self.log(f"[*] Scanning host {host}...")
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(self.scan_port_logic, host, port, service)
                           for port, service in COMMON_PORTS.items()]
                for future in futures:
                    future.result()
            
            if host in self.network_scan_results and self.network_scan_results[host]:
                self.log(f"    [+] {host} scan complete. Open ports: {self.network_scan_results[host]}")
            else:
                self.log(f"    [-] {host} scan complete. No open ports found.")

    def scan_specific_port_on_network_logic(self, ip_range, port_to_check):
        """
        Performs a network scan and checks for a specific port on all live hosts.
        """
        live_hosts = self.get_live_hosts(ip_range)
        if not live_hosts:
            self.log("[!] No live hosts found. Exiting.")
            return

        self.log("\n" + "="*50)
        self.log(f"Starting check for port {port_to_check} on all live hosts...")
        self.log("="*50 + "\n")

        service_name = COMMON_PORTS.get(port_to_check, "unknown")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.scan_port_logic, host, port_to_check, service_name)
                       for host in live_hosts]
            for future in futures:
                future.result()

        self.log("\n[+] Scan for specific port complete. Summary of findings:")
        found_hosts_for_port = [ip for ip, ports in self.network_scan_results.items() if port_to_check in ports]
        if found_hosts_for_port:
            for ip in found_hosts_for_port:
                self.log(f"    - Host {ip} has port {port_to_check} open.")
        else:
            self.log("    - No hosts found with the specified port open.")

if __name__ == "__main__":
    app = ReconToolGUI()
    app.mainloop()
