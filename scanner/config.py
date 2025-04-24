PING_TIMEOUT = 1  # seconds
THREADS = 10  # Number of threads for concurrent scanning

# Port scanning configuration
SCAN_TIMEOUT = 1  # seconds
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
FULL_SCAN_RANGE = (1, 1024)  # Full range of ports to scan

KNOWN_VULNERABILITIES = [
    {
        'port': 21,
        'service': 'FTP',
        'type': 'Vulnerability',
        'severity': 'High',
        'description': 'Anonymous FTP login allowed',
        'solution': 'Disable anonymous login in FTP server configuration',
        'banner': r'vsftpd.*'
    },
    {
        'port': 22,
        'service': 'SSH',
        'type': 'Vulnerability',
        'severity': 'Critical',
        'description': 'Weak SSH ciphers enabled',
        'solution': 'Disable weak ciphers in SSH server configuration',
        # No banner regex for SSH
    },
    # Add more known vulnerabilities as needed
    {
        'port': 80,
        'service': 'HTTP',
        'type': 'Vulnerability',
        'severity': 'Medium',
        'description': 'Directory listing enabled',
        'solution': 'Disable directory listing in web server configuration',
        'banner': r'Apache.*'
    },
    {
        'port': 443,
        'service': 'HTTPS',
        'type': 'Vulnerability',
        'severity': 'High',
        'description': 'SSLv3 supported (POODLE vulnerability)',
        'solution': 'Disable SSLv3 in web server configuration',
        # No banner regex for HTTPS
    }
]