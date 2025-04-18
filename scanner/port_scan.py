import socket
import concurrent.futures
from typing import List, Dict, Optional
from config import SCAN_TIMEOUT, COMMON_PORTS

class PortScanner:
    def __init__(self, timeout: float = SCAN_TIMEOUT):
        """
        Initialize the port scanner with a default timeout

        Ags:
            timeout (float): The timeout for socket operations in seconds
        """
        self.timeout = timeout

    def scan_port(self, ip: str, port: int) -> Optional[Dict]:
        """
        Scan a single port on the given IP address

        Args:
            ip (str): The IP address to scan
            port (int): The port number to scan

        Returns:
            Optional[Dict]: Dictionary with port info if open, None if closed
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    banner = self._grab_banner(sock, ip, port)
                    return {
                        'port': port,
                        'status': 'open',
                        'banner': banner,
                        'service': self._identify_service(port, banner),
                    }
        except (socket.timeout, ConnectionRefusedError):
            pass
        except Exception as e:
            return {
                'port': port,
                'status': 'error',
                'error': str(e),
            }
        
        return None
    
    def _grab_banner(self, sock: socket.socket, ip: str, port: int) -> Optional[str]:
        """
        Attempt to grab the service banner from the socket

        Args:
            sock (socket.socket): The socket object
            ip (str): The IP address
            port (int): The port number

        Returns:
            Optional[str]: The service banner if available, None otherwise
        """
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            if banner:
                return banner
        
            if port == 80:
                sock.send(b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
            elif port == 21:
                sock.send(b'USER anonymous\r\n')
            return sock.recv(1024).decode('utf-8').strip()
        
        except:
            return None
        
    def _identify_service(self, port: int, banner: str) -> str:
        """
        identify the service based on the port and banner

        Args:
            port (int): The port number
            banner (str): The service banner

        Returns:
            str: The service name
        """
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-alt',
        }

        if banner:
            banner = banner.lower()
            if 'apache' in banner or 'httpd' in banner:
                return 'Apache HTTP Server'
            elif 'nginx' in banner:
                return 'Nginx HTTP Server'
            elif 'mysql' in banner:
                return 'MySQL Database'
            elif 'postgresql' in banner:
                return 'PostgreSQL Database'
            elif 'ftp' in banner:
                return 'FTP Server'
            
        return common_services.get(port, 'Unknown Service')
    
    def scan_ports(self, ip: str, ports: List[int] = None, max_threads: int = 100) -> List[Dict]:
        """
        Scan multiple ports on the given IP address

        Args:
            ip (str): The IP address to scan
            ports (List[int]): List of port numbers to scan, defaults to common ports
            max_threads (int): Maximum number of threads to use for scanning

        Returns:
            List[Dict]: List of dictionaries with port info
        """
        if ports is None:
            ports = COMMON_PORTS
        
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in ports}
            
            for future in concurrent.future_to_port.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except Exception as e:
                    print(f"Error scanning port {port}: {e}")
        return sorted(open_ports, key=lambda x: x['port'])
    

    def scan_ip_range(self, ip_range: List[str], ports: List[int] = None) -> Dict[str, List[Dict]]:
        """
        Scan multiple IP addresses in a given range

        Args:
            ip_range (List[str]): List of IP addresses to scan
            ports (List[int]): List of port numbers to scan, defaults to common ports

        Returns:
            Dict[str, List[Dict]]: Dictionary with IP addresses as keys and lists of open ports as values
        """
        results = {}
        
        for ip in ip_range:
            open_ports = self.scan_ports(ip, ports)
            if open_ports:
                results[ip] = open_ports
        
        return results
    