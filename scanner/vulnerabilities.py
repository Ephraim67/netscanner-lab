import re
# from .config import KNOWN_VULNERABILITIES
from .config import KNOWN_VULNERABILITIES


class VulnerabilityScanner:
    def __init__(self):
        self.vuln_db = KNOWN_VULNERABILITIES  # A dictionary of known vulnerabilities

    def scan(self, scan_results):
        """Scan the results of a port scan for known vulnerabilities."""
        vuln_reports = {}
        
        for host, ports in scan_results.items():
            host_vulns = []
            for port_info in ports:
                if port_info['status'] == 'open':
                    vulns = self._check_vulnerabilities(port_info['port'], port_info.get('banner', ''))
                    if vulns:
                        host_vulns.extend(vulns)

            if host_vulns:
                vuln_reports[host] = host_vulns

        return vuln_reports
    
    def check_port_vulnerabilities(self, port_info):
        """Check a single port for known vulnerabilities."""
        vulnerabilities = []

        # Check against known vulnerabilities
        for vuln in self.vuln_db:
            if (vuln['port'] == port_info['port'] or
                vuln['service'].lower() in port_info['service'].lower()):

                # Check if the banner matches the vulnerability pattern
                if 'banner' in vuln and vuln['banner']:
                    if re.search(vuln['banner'], port_info.get('banner', ''), re.IGNORECASE):
                        vulnerabilities.append({
                            'port': port_info['port'],
                            'service': port_info['service'],
                            'type': vuln['type'],
                            'severity': vuln['severity'],
                            'description': vuln['description'],
                            'solution': vuln['solution'],

                        })
                else:
                    vulnerabilities.append({
                        'port': port_info['port'],
                        'service': port_info['service'],
                        'type': vuln['type'],
                        'severity': vuln['severity'],
                        'description': vuln['description'],
                        'solution': vuln['solution'],
                })
        return vulnerabilities
