import scapy.all as scapy

def packet_handler(packet):
    if packet.haslayer(scapy.IP):
        IpSrc = packet[scapy.IP].src
        IpDst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"IP Source: {IpSrc}, IP Destination: {IpDst}, Protocol:{protocol}")

        if packet.haslayer(scapy.TCP):
            TcpSrcPort = packet[scapy.TCP].sport
            TcpDstPort = packet[scapy.TCP].dport
            print(f"TCP Source Port: {TcpSrcPort}, TCP Destination Port: {TcpDstPort}")

        elif packet.haslayer(scapy.UDP):
            UdpSrcPort = packet[scapy.UDP].sport
            UdpDstPort = packet[scapy.UDP].dport
            print(f"UDP Source Port: {UdpSrcPort}, UDP Destination Port: {UdpDstPort}")

        elif packet.haslayer(scapy.ICMP):
            icmpType = packet[scapy.ICMP].type
            icmpCode = packet[scapy.ICMP].code
            print(f"ICMP Type: {icmpType}, ICMP Code: {icmpCode}")

# Replace 'abc' with the appropriate network interface
interface = 'Intel(R) Dual Band Wireless-AC 8265'

scapy.sniff(iface=interface, store=False, prn=packet_handler,count=10)