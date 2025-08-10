#
# Advanced Network Reconnaissance Tool
# This script combines network host discovery with multithreaded port scanning.
#
# This script requires the Scapy library.
# To install, run: pip install scapy
#
# IMPORTANT: This script requires elevated privileges to run (e.g., 'sudo python3 your_script_name.py')
# as Scapy needs to send and receive raw network packets.
#
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import sys
from scapy.all import ARP, Ether, srp
from scapy.layers.l2 import getmacbyip

# --- Global Data Structures ---
# Lock for thread-safe access to the shared list
found_ports_lock = Lock()
# List to store all open ports found during the scan
found_ports = []
# Dictionary to store results from the network scan
network_scan_results = {}

# A dictionary of common ports and their service names.
# You can easily expand this list.
COMMON_PORTS = {
    # FTP
    20: 'ftp-data',
    21: 'ftp',
    # SSH & Telnet
    22: 'ssh',
    23: 'telnet',
    # Email
    25: 'smtp',
    110: 'pop3',
    143: 'imap',
    587: 'smtps',
    993: 'imaps',
    995: 'pop3s',
    # DNS, DHCP, and Web
    53: 'dns',
    67: 'dhcp',
    68: 'dhcp-client',
    80: 'http',
    443: 'https',
    8443: 'https-alt',
    # Windows & Remote Access
    139: 'netbios',
    445: 'smb',
    3389: 'rdp',
    5900: 'vnc',
    # Databases & Media
    3306: 'mysql',
    5432: 'postgresql',
    554: 'rtsp',
    # Alternative Web
    8080: 'http-alt',
}

# --- Helper Functions ---
def find_live_hosts(ip_range):
    """
    Scans a given IP range for live hosts and returns a list of dictionaries
    with their IP and MAC.
    
    Args:
        ip_range (str): The IP range to scan (e.g., '192.168.1.0/24').
        
    Returns:
        list: A list of dictionaries, each representing a live host.
    """
    print(f"[*] Scanning {ip_range} for live hosts using ARP requests...")
    
    arp_request = ARP(pdst=ip_range)
    ether_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_broadcast / arp_request

    answered, unanswered = srp(packet, timeout=2, verbose=False)
    
    live_hosts = []
    for sent, received in answered:
        host_ip = received.psrc
        host_mac = received.hwsrc
        live_hosts.append({'ip': host_ip, 'mac': host_mac})
        print(f"    - Found host: IP={host_ip}, MAC={host_mac}")
        
    print(f"[*] Network scan complete. Found {len(live_hosts)} live hosts.")
    return live_hosts

def scan_port(host, port, service_name):
    """
    Worker function to scan a single port on a given host.
    Uses a socket to try and connect, indicating an open port on success.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((host, port))
            print(f"[{host}] Port {port} is open.")
            with found_ports_lock:
                # Store the result in a dictionary keyed by IP for better organization
                if host not in network_scan_results:
                    network_scan_results[host] = []
                network_scan_results[host].append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass

def scan_single_host(host):
    """
    Orchestrates the port scanning for a single host using multithreading.
    """
    print(f"[*] Starting multithreaded scan on target: {host}...\n")
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        for port, service in COMMON_PORTS.items():
            executor.submit(scan_port, host, port, service)

    if host in network_scan_results:
        print(f"\n[+] Scan complete for {host}. Found {len(network_scan_results[host])} open ports.")
        
    else:
        print(f"\nNo open ports found on {host}.")

def full_scan_on_network(ip_range):
    """
    Performs a network scan and then a full port scan on all live hosts.
    """
    live_hosts = find_live_hosts(ip_range)
    if not live_hosts:
        print("[!] No live hosts found. Exiting.")
        return

    print("\n" + "="*50)
    print("Starting full port scan on all live hosts...")
    print("="*50 + "\n")

    for host in live_hosts:
        # Reset the found_ports list for each host to avoid contamination
        with found_ports_lock:
            found_ports.clear()
        
        print(f"[*] Scanning host {host['ip']}...")
        with ThreadPoolExecutor(max_workers=50) as executor:
            for port, service in COMMON_PORTS.items():
                executor.submit(scan_port, host['ip'], port, service)
        
        if host['ip'] in network_scan_results and network_scan_results[host['ip']]:
            print(f"    [+] {host['ip']} scan complete. Open ports: {network_scan_results[host['ip']]}")
        else:
            print(f"    [-] {host['ip']} scan complete. No open ports found.")

def scan_specific_port_on_network(ip_range, port_to_check):
    """
    Performs a network scan and checks for a specific port on all live hosts.
    """
    live_hosts = find_live_hosts(ip_range)
    if not live_hosts:
        print("[!] No live hosts found. Exiting.")
        return

    print("\n" + "="*50)
    print(f"Starting check for port {port_to_check} on all live hosts...")
    print("="*50 + "\n")

    with ThreadPoolExecutor(max_workers=50) as executor:
        for host in live_hosts:
            service_name = COMMON_PORTS.get(port_to_check, "unknown")
            executor.submit(scan_port, host['ip'], port_to_check, service_name)

    print("\n[+] Scan for specific port complete. Summary of findings:")
    if network_scan_results:
        for ip, ports in network_scan_results.items():
            if ports:
                print(f"    - Host {ip} has port {port_to_check} open.")
    else:
        print("    - No hosts found with the specified port open.")

def main():
    """
    Main function to parse command-line arguments and run the scanner.
    """
    parser = argparse.ArgumentParser(description='Advanced Network Reconnaissance Tool. Scans hosts and ports.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--single', metavar='<host>', help='Scan a single host for a list of common ports.')
    group.add_argument('--full', metavar='<range>', help='Scan a network range to discover live hosts.')
    parser.add_argument('--show', metavar='<port>', type=int, help='When used with --full, shows if a specific port is open on live hosts.')
    
    args = parser.parse_args()
    
    if args.single:
        # Check if the --show argument is used incorrectly
        if args.show:
            print("[!] The --show argument is not applicable for a --single scan.")
            print("[!] Ignoring --show and performing a full common-port scan.")
        scan_single_host(args.single)
        
    elif args.full:
        if args.show:
            # Full scan with a specific port check
            scan_specific_port_on_network(args.full, args.show)
        else:
            # Full network scan and full port scan on live hosts
            full_scan_on_network(args.full)
        
    print("\n[+] Program finished.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")
