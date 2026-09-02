from scapy.all import sniff, IP, TCP, UDP, ICMP

def show_packet(packet):
    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    length = len(packet)

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = str(packet[IP].proto)

    print(f"{src:15} -> {dst:15} | {protocol:5} | {length} bytes")


print("CodeAlpha - Basic Network Sniffer")
print("Capturing packets visible to this host. Press Ctrl+C to stop.")

sniff(prn=show_packet, store=False)