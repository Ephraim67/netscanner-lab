import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
from .config import PINGTIMEOUT, THREADS

class NetworkDiscovery:
    def __init__(self):
        """
        Initialize the network discovery class.
        """
        self.timeout = PINGTIMEOUT  # Default timeout for pinging hosts
        self.max_threads = THREADS


    def discovery(self, target: str):
        """
        Discover hosts in the given target range.

        Args:
            target (str): The target IP address or CIDR range to scan.

        Returns:
            List[str]: A list of discovered hosts.
        """
        try:
            if '/' in target: # CIDR notation
                return self._scan_cidr(target)
            elif '-' in target: # Range of IP addresses
                return self.scan_ip_range(target)
            else: # Single IP address
                return [target] if self.is_host_alive(target) else []
        
        except Exception as e:
            raise ValueError(f"Invalid target format: {target}. Error: {e}") from e
        
    def scan_network(self, cidr):
        """Scan all hosts in a given CIDR range."""
        network = ipaddress.ip_network(cidr, strict=False)
        # hosts = [str(host) for host in network.hosts() if self.is_host_alive(str(host))]
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = executor.map(self.is_host_alive, network.hosts())
            return [str(host) for host, alive in zip(network.hosts(), results) if alive]
        
    def host_alive(self, ip):
        """Check if a host is alive using using ICMP ping."""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', str(self.timeout), str(ip)]
        return subprocess.call(command, stdout=subprocess.DEVNULL) == 0