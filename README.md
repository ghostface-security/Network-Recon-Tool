# Network-Recon-Tool

An advanced network reconnaissance tool that combines host discovery with multithreaded port scanning. This script is an enhanced version of a standard port scanner, using the Scapy library to efficiently find live hosts on a network before proceeding with a port scan.

**⚠️ Ethical Use Warning**

This tool is provided for educational and ethical purposes only. It is intended for use in controlled, authorized environments to test and understand network security principles. Unauthorized scanning of networks is illegal and unethical. The developer is not responsible for any misuse or damage caused by this program. By using this tool, you agree to assume full responsibility for your actions.

## Features

* **Host Discovery**: Efficiently identifies live hosts on a network using ARP requests, which is faster and more reliable on a local network than a simple ping sweep.
* **Multithreaded Scanning**: Uses a thread pool to perform port scans, allowing multiple ports to be checked at once for significantly faster results.
* **Flexible Scanning Modes**: Supports scanning a single host, a full network for common open ports, or a full network for a specific port.
* **Service Identification**: Includes a dictionary of common ports to provide a service name (e.g., ssh, http) along with the port number.

## Requirements

This script requires the Scapy library, which needs to be installed separately. To install Scapy, run the following command:

```bash
pip install scapy

Usage
This script requires elevated privileges to run (e.g., sudo) because Scapy needs to send and receive raw network packets.
Basic Syntax
sudo python3 netrecon.py [OPTIONS]

Options
| Option | Description |
|---|---|
| --single <host> | Scans a single host for a list of common ports. |
| --full <range> | Discovers live hosts within a network range and scans them for common ports. |
| --show <port> | Used with --full, this option checks for a specific port on all discovered live hosts. |
Examples
 * Scan a single host for common ports:
   sudo python3 netrecon.py --single 192.168.1.10

 * Scan an entire network for common ports on all live hosts:
   sudo python3 netrecon.py --full 192.168.1.0/24

 * Check for a specific port (e.g., 80) on all live hosts in a network:
   sudo python3 netrecon.py --full 192.168.1.0/24 --show 80

