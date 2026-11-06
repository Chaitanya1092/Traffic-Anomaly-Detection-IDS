import unittest

from scapy.all import DNS, DNSQR, Ether, IP, IPv6, TCP, UDP

from utils.packet_processor import PacketProcessor


class PacketProcessorTests(unittest.TestCase):
    def test_detects_dns_over_udp(self):
        packet = (
            Ether()
            / IP(src="192.0.2.10", dst="192.0.2.53")
            / UDP(sport=53000, dport=53)
            / DNS(qd=DNSQR(qname="example.com"))
        )

        packet_info = PacketProcessor.parse_packet(packet)

        self.assertEqual(packet_info["protocol"], "DNS")
        self.assertTrue(packet_info["is_dns"])
        self.assertEqual(packet_info["dns_query"], "example.com")

    def test_detects_dns_over_tcp(self):
        packet = (
            Ether()
            / IP(src="192.0.2.10", dst="192.0.2.53")
            / TCP(sport=53000, dport=53)
            / DNS(qd=DNSQR(qname="example.com"))
        )

        packet_info = PacketProcessor.parse_packet(packet)

        self.assertEqual(packet_info["protocol"], "DNS")
        self.assertTrue(packet_info["is_dns"])
        self.assertEqual(packet_info["dns_query"], "example.com")

    def test_extracts_ipv6_addresses(self):
        packet = (
            Ether()
            / IPv6(src="2001:db8::1", dst="2001:db8::53")
            / UDP(sport=53000, dport=53)
            / DNS(qd=DNSQR(qname="example.com"))
        )

        packet_info = PacketProcessor.parse_packet(packet)

        self.assertEqual(packet_info["src_ip"], "2001:db8::1")
        self.assertEqual(packet_info["dst_ip"], "2001:db8::53")


if __name__ == "__main__":
    unittest.main()
