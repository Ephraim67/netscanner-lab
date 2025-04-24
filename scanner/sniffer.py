import sys
import json
from scapy.all import sniff, IP, TCP

# Function to handle each packet
def handle_packet(packet, log):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        packet_info = {
            "protocol": "TCP",
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port
        }

        log.write(json.dumps(packet_info) + "\n")

# Main sniffing function
def main(interface, verbose=False):
    logfile_name = f"sniffer_{interface}_log.json"

    with open(logfile_name, 'w') as logfile:
        try:
            sniff(
                iface=interface,
                prn=lambda pkt: handle_packet(pkt, logfile),
                store=0,
                verbose=verbose
            )
        except KeyboardInterrupt:
            print("\n[+] Sniffing stopped by user.")
            sys.exit(0)

# Entry point
if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)

    interface = sys.argv[1]
    verbose = len(sys.argv) == 3 and sys.argv[2].lower() == "verbose"

    main(interface, verbose)
