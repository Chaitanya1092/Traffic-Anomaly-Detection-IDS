import time
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR

class PacketProcessor:
    @staticmethod
    def parse_packet(packet):
        """
        Parses a raw Scapy packet and extracts metadata.
        Returns a dictionary with packet details or None if basic headers are missing.
        """
        try:
            packet_info = {
                "timestamp": float(packet.time) if packet.time else time.time(),
                "size": len(packet),
                "src_mac": "",
                "dst_mac": "",
                "src_ip": "",
                "dst_ip": "",
                "src_port": None,
                "dst_port": None,
                "protocol": "OTHER",
                "is_arp": False,
                "is_icmp": False,
                "is_dns": False,
                "dns_query": "",
                "dns_type": "",
                "arp_op": None,
                "arp_psrc": "",
                "arp_pdst": "",
                "arp_hwsrc": "",
                "arp_hwdst": ""
            }

            # Ethernet Layer
            if packet.haslayer(Ether):
                packet_info["src_mac"] = packet[Ether].src
                packet_info["dst_mac"] = packet[Ether].dst

            # ARP Layer
            if packet.haslayer(ARP):
                packet_info["protocol"] = "ARP"
                packet_info["is_arp"] = True
                packet_info["arp_op"] = packet[ARP].op  # 1 = who-has, 2 = is-at
                packet_info["arp_psrc"] = packet[ARP].psrc
                packet_info["arp_pdst"] = packet[ARP].pdst
                packet_info["arp_hwsrc"] = packet[ARP].hwsrc
                packet_info["arp_hwdst"] = packet[ARP].hwdst
                # For ARP, source/destination "IPs" are psrc/pdst
                packet_info["src_ip"] = packet[ARP].psrc
                packet_info["dst_ip"] = packet[ARP].pdst
                return packet_info

            # IP / IPv6 Layers
            has_ip = False
            if packet.haslayer(IP):
                packet_info["src_ip"] = packet[IP].src
                packet_info["dst_ip"] = packet[IP].dst
                has_ip = True
            elif packet.haslayer(IPv6):
                packet_info["src_ip"] = packet[IPv6].src
                packet_info["dst_ip"] = packet[IPv6].dst
                has_ip = True

            if not has_ip and not packet_info["src_mac"]:
                # If neither IP nor Ethernet MAC is captured, skip
                return None

            # TCP Layer
            if packet.haslayer(TCP):
                packet_info["protocol"] = "TCP"
                packet_info["src_port"] = int(packet[TCP].sport)
                packet_info["dst_port"] = int(packet[TCP].dport)
            # UDP Layer
            elif packet.haslayer(UDP):
                packet_info["protocol"] = "UDP"
                packet_info["src_port"] = int(packet[UDP].sport)
                packet_info["dst_port"] = int(packet[UDP].dport)

            if packet.haslayer(DNS):
                packet_info["is_dns"] = True
                packet_info["protocol"] = "DNS"
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname
                    if isinstance(qname, bytes):
                        packet_info["dns_query"] = qname.decode('utf-8', errors='ignore').rstrip('.')
                    else:
                        packet_info["dns_query"] = str(qname).rstrip('.')
                    packet_info["dns_type"] = packet[DNSQR].qtype

            # ICMP Layer
            elif packet.haslayer(ICMP):
                packet_info["protocol"] = "ICMP"
                packet_info["is_icmp"] = True
                # Use type and code as ports just to fit standard reporting
                packet_info["src_port"] = int(packet[ICMP].type)
                packet_info["dst_port"] = int(packet[ICMP].code)

            return packet_info
            
        except Exception:
            # Silently catch parsing issues on corrupted packets
            return None
