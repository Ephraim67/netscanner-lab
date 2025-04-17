import socket


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
    
    def banner()