import socket
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import pyfiglet
import argparse
import logging

init()

COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Command Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP",
    80: "HTTP",
    90: "HTTP Alternate (Possible use to bypass firewall)",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "Microsoft-DS (SMB)",
    465: "SMTPS",
    514: "Syslog",
    554: "RTSP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1025: "MSP (Microsoft RPC - EPMAP)",
    1149: "VPN",
    1433: "Microsoft SQL Server",
    1434: "Microsoft SQL Monitor",
    1521: "Oracle Database",
    1723: "PPTP",
    2049: "NFS",
    2181: "Apache ZooKeeper",
    2379: "etcd",
    2380: "etcd (Leader Communication)",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion (SVN)",
    4040: "Spark Web UI",
    4369: "Erlang Port Mapper Daemon",
    5000: "HTTP Alternative (Common APIs)",
    5432: "PostgreSQL",
    5672: "RabbitMQ (AMQP)",
    5900: "VNC",
    5984: "CouchDB",
    6080: "OpenStack Horizon",
    6379: "Redis",
    6443: "Kubernetes API Server",
    6667: "IRC",
    7001: "WebLogic Server",
    8000: "HTTP Alternative",
    8080: "HTTP Alternative",
    8081: "HTTP Proxy Alternative",
    8443: "HTTPS Alternative",
    9000: "SonarQube",
    9092: "Apache Kafka",
    9200: "Elasticsearch",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    32400: "Plex",
    3333: "Ethereum Wallet RPC (Cryptocurrency)",
    4444: "Oracle WebLogic (often used by attackers for backdoors)",
    5555: "Android Debug Bridge (ADB)",
    6660: "Internet Relay Chat (IRC) - Often used by malware",
    8088: "CouchDB (admin interface)",
    8888: "HTTP Alt (possible backdoor)",
    9999: "Daemon Port (often used by malware)",
    10080: "HTTP (Common HTTP Proxy)",
    1080: "SOCKS Proxy",
    15000: "Nessus (Vulnerability Scanner)",
    20000: "Webmin (Admin Panel)",
    31337: "Back Orifice (Remote Admin Tool)",
    33333: "Backup Exec (Admin Panel)",
    44444: "Backdoor (Possible use by hackers)",
    55555: "Possible backdoor (can be used by hackers)",
    66666: "Possible malware communication",
    70000: "Possible backdoor",
    90000: "Unknown, can be used by attackers",
    100000: "Highly suspicious (Could be used for malicious services)"
}

LOG_FILE = f"portscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def find_nmap():
    return shutil.which("nmap")

NMAP_PATH = find_nmap()

def validate_target(target):
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ip_pattern.match(target):
        return target
    try:
        socket.gethostbyname(target)
        return target
    except socket.error:
        return None

def validate_port(port):
    return isinstance(port, int) and 1 <= port <= 65535

def scan_port(ip, port, timeout=1, silent=False, results=None):
    if results is None:
        results = []
    try:
        start_time = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result_code = s.connect_ex((ip, port)) 
            if result_code == 0:
                result = f"Port {port}: OPEN ({COMMON_PORTS.get(port, 'Unknown')})"
                if not silent:
                    print(Fore.GREEN + result)
                results.append(result)
                service_info = get_service_info(ip, port)
                if service_info and not silent:
                    print(Fore.CYAN + f"  Service details: {service_info}")
                if service_info:
                    results.append(f"  Service details: {service_info}")
            else:
                result = f"Port {port}: CLOSED"
                if not silent:
                    print(Fore.RED + result)
                results.append(result)
        duration = round(time.time() - start_time, 2)
        if not silent and result_code == 0:
            print(Fore.CYAN + f"Scan completed in {duration}s for port {port}")
    except Exception as e:
        result = f"Port {port}: ERROR ({str(e)})"
        if not silent:
            print(Fore.RED + result)
        results.append(result)
    return results

def get_service_info(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            return f"Service banner: {banner}" if banner else None
    except:
        return None

def create_results_directory():
    base_dir = "scan_results"
    date_dir = os.path.join(base_dir, datetime.now().strftime("%Y-%m-%d"))
    os.makedirs(date_dir, exist_ok=True)
    return date_dir

def save_results_to_file(target, results, folder_path, nmap_output=None):
    scan_number = len(os.listdir(folder_path)) + 1
    file_path = os.path.join(folder_path, f"scan_{scan_number}.txt")
    with open(file_path, "w") as f:
        f.write(f"Scan performed on: {target}\n")
        f.write(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("\n".join(results))
        if nmap_output:
            f.write("\n\n=== Nmap Scan ===\n")
            f.write(nmap_output)
    logging.info(f"Results saved to {file_path}")
    print(Fore.GREEN + f"Results saved to '{file_path}'.")

def advanced_scan(ip, ports, scan_type="normal"):
    if not NMAP_PATH:
        print(Fore.RED + "Nmap not found. Install it for advanced scanning.")
        return None
    try:
        print(Fore.YELLOW + "\nLaunching Nmap scan...")
        ports_str = ",".join(map(str, ports))
        timing = "-T4" if scan_type == "quick" else "-T1"
        cmd = [NMAP_PATH, timing, "-sV", "-p", ports_str, ip]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(Fore.CYAN + result.stdout)
        logging.info(f"Nmap scan completed for {ip} on ports {ports_str}")
        return result.stdout
    except Exception as e:
        logging.error(f"Advanced scan error: {e}")
        print(Fore.RED + f"Error during advanced scan: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Port Scanner - Scan open ports on a target")
    parser.add_argument("-t", "--target", help="Target IP or domain")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., '80,443' or '1-100')")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode (no live output)")
    parser.add_argument("-n", "--nmap", choices=["quick", "detailed"], help="Run Nmap scan (quick/detailed)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("-o", "--output", action="store_true", help="Save results to file")
    
    args = parser.parse_args()

    title = pyfiglet.figlet_format("Port Scanner", font="slant")
    print(Fore.RED + title)
    print(Fore.CYAN + "=== Port Scanner ===")

    if args.target:
        target = validate_target(args.target)
        if not target:
            print(Fore.RED + "Invalid IP or domain.")
            return

        if args.ports:
            if "-" in args.ports:
                start, end = map(int, args.ports.split("-"))
                if not (validate_port(start) and validate_port(end) and start <= end):
                    print(Fore.RED + "Invalid port range.")
                    return
                ports_to_scan = range(start, end + 1)
            else:
                ports_to_scan = [int(p) for p in args.ports.split(",") if validate_port(int(p))]
        else:
            ports_to_scan = list(COMMON_PORTS.keys())

        results = []
        print(Fore.GREEN + f"\nScanning {target} for specified ports...\n")
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            for port in ports_to_scan:
                executor.submit(scan_port, target, port, args.silent, results)

        nmap_output = advanced_scan(target, ports_to_scan, args.nmap) if args.nmap else None
        if args.output:
            save_results_to_file(target, results, create_results_directory(), nmap_output)
    else:
        print(Fore.GREEN + "Welcome to the Port Scanner!\n")
        target = input(Fore.YELLOW + "Enter target IP or domain: ")
        while not validate_target(target):
            print(Fore.RED + "Invalid IP or domain. Try again.")
            target = input(Fore.YELLOW + "Enter target IP or domain: ")

        range_choice = input(Fore.YELLOW + "Scan a port range? (yes/no): ").lower()
        if range_choice in ["no", "n"]:
            ports_to_scan = list(COMMON_PORTS.keys())
        else:
            try:
                start = int(input(Fore.YELLOW + "Start port: "))
                end = int(input(Fore.YELLOW + "End port: "))
                if not (validate_port(start) and validate_port(end) and start <= end):
                    raise ValueError
                ports_to_scan = range(start, end + 1)
            except ValueError:
                print(Fore.RED + "Please enter valid port numbers.")
                return

        silent = input(Fore.YELLOW + "Silent mode? (yes/no): ").lower() in ["yes", "y"]
        workers = int(input(Fore.YELLOW + "Number of threads (default 100): ") or 100)

        results = []
        print(Fore.GREEN + f"\nScanning {target} for specified ports...\n")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for port in ports_to_scan:
                executor.submit(scan_port, target, port, silent, results)

        print(Fore.GREEN + "\nScan completed.\n")
        if NMAP_PATH and input(Fore.YELLOW + "Run an advanced Nmap scan? (yes/no): ").lower() in ["yes", "y"]:
            scan_type = input(Fore.YELLOW + "Nmap scan type: quick or detailed? (quick/detailed): ").lower()
            nmap_output = advanced_scan(target, ports_to_scan, scan_type)
        else:
            nmap_output = None

        if input(Fore.YELLOW + "Save results to file? (yes/no): ").lower() in ["yes", "y"]:
            save_results_to_file(target, results, create_results_directory(), nmap_output)

    print(Fore.CYAN + "\n=== Scan completed! ===")
    print(Fore.GREEN + "Shoutouts to: ChatNoir, Lowleys, KyotoSH, Wakm")
    print(Fore.MAGENTA + "Ryuji is the creator of this tool!")
    print(Fore.YELLOW + "Thanks for using this port scanner! See you soon!")

if __name__ == "__main__":
    main()
