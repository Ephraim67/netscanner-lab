import argparse
from scanner.discovery import NetworkDiscovery
from scanner.port_scan import PortScanner
from scanner.vulnerabilities import VulnerabilityScanner
from scanner.reporting import ReportGenerator
# from utils.logger import setup_logging

def main():
    # setup_logging()
    
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("target", help="IP address, range, or subnet to scan")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., '80,443' or '1-1000')")
    parser.add_argument("-o", "--output", 
                   choices=['html', 'csv'],  # Only allow these file outputs
                   help="Save report to file (html or csv)")
    parser.add_argument("--fast", action="store_true", help="Fast scan (common ports only)")
    parser.add_argument("--full", action="store_true", help="Full scan (all ports + deep vuln check)")
    
    args = parser.parse_args()
    
    # Phase 1: Network Discovery
    print("[*] Starting network discovery...")
    discovery = NetworkDiscovery()
    live_hosts = discovery.discover(args.target)
    
    # Phase 2: Port Scanning
    print("[*] Starting port scanning...")
    port_scanner = PortScanner()
    
    if args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = "common" if args.fast else "full"
    
    scan_results = {}
    for host in live_hosts:
        scan_results[host] = port_scanner.scan_ports(host, ports)
    
    # Phase 3: Vulnerability Detection
    print("[*] Scanning for vulnerabilities...")
    vuln_scanner = VulnerabilityScanner()
    vuln_results = vuln_scanner.scan(scan_results)
    
    # Phase 4: Reporting
    print("[*] Generating report...")
    report = ReportGenerator()
    report.generate(vuln_results, args.output)
    
    print(f"[+] Scan completed. Report saved as {args.output}")

def parse_ports(port_str):
    """Parse port string into list of integers"""
    ports = []
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end+1))
        else:
            ports.append(int(part))
    return ports

if __name__ == "__main__":
    main()