import nmap
import requests
import socket
import json
import datetime
import os
import re

# Create directory for reports if it doesn't exist
if not os.path.exists("reports"):
    os.makedirs("reports")

# Configuration constants
VULN_DATABASE = {
    "Apache": "2.4.41",
    "nginx": "1.18.0",
    "OpenSSH": "8.2"
}
COMMON_SECURITY_HEADERS = ["X-Content-Type-Options", "X-XSS-Protection", "Strict-Transport-Security"]

# Port Scanning using nmap
def scan_open_ports(ip_address):
    scanner = nmap.PortScanner()
    scanner.scan(ip_address, '1-1024')  # Scan common ports
    open_ports = []

    for port in scanner[ip_address]['tcp']:
        if scanner[ip_address]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    return open_ports

# Check software version against vulnerability database
def check_software_version(service, version):
    if service in VULN_DATABASE:
        if version < VULN_DATABASE[service]:
            return True
    return False

# Basic HTTP headers scan
def scan_http_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        missing_headers = [header for header in COMMON_SECURITY_HEADERS if header not in headers]
        return missing_headers
    except requests.RequestException:
        return None

# Banner grabbing (version detection) using socket
def get_service_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except socket.error:
        return None

# Generate scan report
def generate_report(scan_results, filename="report.json"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filepath = os.path.join("reports", f"{filename}_{timestamp}.json")
    with open(filepath, "w") as file:
        json.dump(scan_results, file, indent=4)
    print(f"Report saved to {filepath}")

# Main function
def main():
    target = input("Enter the target IP or domain (e.g., 192.168.1.1 or http://example.com): ").strip()
    target = re.sub(r'^https?://', '', target)  # Remove protocol if included
    scan_type = input("Select scan type (1) Port Scan (2) HTTP Headers Scan (3) Full Scan: ").strip()

    results = {
        "target": target,
        "scan_date": str(datetime.datetime.now()),
        "open_ports": [],
        "insecure_software": [],
        "missing_headers": []
    }

    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Unable to resolve the target. Please check the domain or IP address and try again.")
        return

    if scan_type in ["1", "3"]:
        print("Scanning for open ports...")
        open_ports = scan_open_ports(ip_address)
        results["open_ports"] = open_ports
        print(f"Open ports: {open_ports}")

        for port in open_ports:
            banner = get_service_banner(ip_address, port)
            if banner:
                service, version = (banner.split("/", 1) if "/" in banner else (banner, "unknown"))
                if check_software_version(service, version):
                    results["insecure_software"].append({"service": service, "version": version})
                    print(f"Insecure software found: {service} {version}")

    if scan_type in ["2", "3"]:
        print("Checking HTTP security headers...")
        missing_headers = scan_http_headers("http://" + target)  # Add protocol back for HTTP request
        if missing_headers:
            results["missing_headers"] = missing_headers
            print(f"Missing security headers: {missing_headers}")

    generate_report(results)

if __name__ == "__main__":
    main()
