import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import sys
import time
import threading

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

def log(message):
    """
    Prints a message to the console.
    """
    print(message)

def is_host_live(host):
    """
    Checks if a host is live by attempting to connect to a common port (80).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.connect((host, 80))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

def get_live_hosts(ip_range):
    """
    Discovers live hosts in a given IP range.
    """
    log(f"[*] Discovering live hosts in {ip_range}...")
    live_hosts = []
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(is_host_live, str(ip)): str(ip) for ip in network.hosts()}
            for future in futures:
                ip = futures[future]
                if future.result():
                    live_hosts.append(ip)
                    log(f"    - Found live host: {ip}")
    except ValueError as e:
        log(f"[!] Invalid IP address or range: {e}")
        return []

    log(f"[*] Host discovery complete. Found {len(live_hosts)} live hosts.")
    return live_hosts

def scan_port_logic(host, port, service_name, results_lock, results):
    """
    Worker function to scan a single port on a given host and update results.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((host, port))
            with results_lock:
                results.setdefault(host, []).append(port)
            log(f"[{host}] Port {port} is open ({service_name}).")
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

def scan_single_host_logic(host):
    """
    Orchestrates the port scanning for a single host.
    """
    log(f"[*] Starting multithreaded scan on target: {host}...\n")
    start_time = time.time()
    network_scan_results = {}
    results_lock = threading.Lock()
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port_logic, host, port, service, results_lock, network_scan_results)
                   for port, service in COMMON_PORTS.items()]
        for future in futures:
            future.result()

    end_time = time.time()
    elapsed_time = end_time - start_time
    
    if host in network_scan_results and network_scan_results[host]:
        log(f"\n[+] Scan complete for {host} in {elapsed_time:.2f} seconds. Found {len(network_scan_results[host])} open ports: {sorted(network_scan_results[host])}")
    else:
        log(f"\n[-] No open ports found on {host} in {elapsed_time:.2f} seconds.")

def full_scan_on_network_logic(ip_range):
    """
    Performs a network scan and then a full port scan on all live hosts.
    """
    start_time = time.time()
    live_hosts = get_live_hosts(ip_range)
    if not live_hosts:
        log("[!] No live hosts found. Exiting.")
        return

    log("\n" + "="*50)
    log("Starting full port scan on all live hosts...")
    log("="*50 + "\n")
    
    network_scan_results = {}
    results_lock = threading.Lock()

    for host in live_hosts:
        log(f"[*] Scanning host {host}...")
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port_logic, host, port, service, results_lock, network_scan_results)
                       for port, service in COMMON_PORTS.items()]
            for future in futures:
                future.result()
        
        if host in network_scan_results and network_scan_results[host]:
            log(f"    [+] {host} scan complete. Open ports: {sorted(network_scan_results[host])}")
        else:
            log(f"    [-] {host} scan complete. No open ports found.")
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    log(f"\n[+] Full network scan complete in {elapsed_time:.2f} seconds.")

def scan_specific_port_on_network_logic(ip_range, port_to_check):
    """
    Performs a network scan and checks for a specific port on all live hosts.
    """
    start_time = time.time()
    live_hosts = get_live_hosts(ip_range)
    if not live_hosts:
        log("[!] No live hosts found. Exiting.")
        return

    log("\n" + "="*50)
    log(f"Starting check for port {port_to_check} on all live hosts...")
    log("="*50 + "\n")
    
    network_scan_results = {}
    results_lock = threading.Lock()
    service_name = COMMON_PORTS.get(port_to_check, "unknown")

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port_logic, host, port_to_check, service_name, results_lock, network_scan_results)
                   for host in live_hosts]
        for future in futures:
            future.result()

    end_time = time.time()
    elapsed_time = end_time - start_time
    
    log(f"\n[+] Scan for specific port complete in {elapsed_time:.2f} seconds. Summary of findings:")
    found_hosts_for_port = [ip for ip, ports in network_scan_results.items() if port_to_check in ports]
    if found_hosts_for_port:
        for ip in sorted(found_hosts_for_port):
            log(f"    - Host {ip} has port {port_to_check} open.")
    else:
        log(f"    - No hosts found with the specified port {port_to_check} open.")

def main():
    """
    Main function to parse command-line arguments and run the appropriate scan.
    """
    parser = argparse.ArgumentParser(description="A network reconnaissance tool for scanning hosts and ports.", formatter_class=argparse.RawTextHelpFormatter, epilog=
"""Examples:
 * Scan a single host for common ports:
   sudo python3 netrecon.py --single 192.168.1.10

 * Scan an entire network for common ports on all live hosts:
   sudo python3 netrecon.py --full 192.168.1.0/24

 * Check for a specific port (e.g., 80) on all live hosts in a network:
   sudo python3 netrecon.py --full 192.168.1.0/24 --show 80
""")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--single', metavar='<host>', help='Scans a single host for a list of common ports.')
    group.add_argument('--full', metavar='<range>', help='Discovers live hosts within a network range and scans them.')
    
    parser.add_argument('--show', metavar='<port>', type=int, help='Used with --full, this option checks for a specific port on all discovered live hosts.')
    
    args = parser.parse_args()

    if args.single:
        scan_single_host_logic(args.single)
    elif args.full:
        if args.show:
            scan_specific_port_on_network_logic(args.full, args.show)
        else:
            full_scan_on_network_logic(args.full)

if __name__ == "__main__":
    main()