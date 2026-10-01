"""
Simple Packet Sniffer
---------------------
Captures network packets and shows:
  - Source IP and Destination IP
  - Protocol (TCP, UDP, ICMP)
  - Ports
  - Payload (the data inside the packet)

How to run (as Administrator / sudo):
    pip install scapy
    python simple_sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS

# Names for common ports, so we can see WHAT kind of traffic it is
PORT_NAMES = {
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    25: "Email (SMTP)",
}

packet_number = 0          # counts the packets we see
protocol_count = {}        # counts how many TCP / UDP / ICMP we see


def show_packet(packet):
    """This function runs once for every packet captured."""
    global packet_number

    # We only look at packets that have an IP layer
    if IP not in packet:
        return

    packet_number += 1
    src = packet[IP].src      # who sent it
    dst = packet[IP].dst      # who receives it

    # Step 1: find the protocol
    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"      # this is what "ping" uses
        src_port = "-"
        dst_port = "-"
    else:
        protocol = "Other"
        src_port = "-"
        dst_port = "-"

    # Step 2: remember the count for the summary
    protocol_count[protocol] = protocol_count.get(protocol, 0) + 1

    # Step 3: guess the service from the port number
    service = PORT_NAMES.get(dst_port) or PORT_NAMES.get(src_port) or "-"

    # Step 4: print the information
    print("\n" + "=" * 40)
    print(f"Packet #{packet_number}")
    print(f"Source      : {src}:{src_port}")
    print(f"Destination : {dst}:{dst_port}")
    print(f"Protocol    : {protocol}")
    print(f"Service     : {service}")

    # If it is a DNS packet, show the website name being looked up
    if DNS in packet and packet[DNS].qd:
        website = packet[DNS].qd.qname.decode()
        print(f"DNS lookup  : {website}")

    # Step 5: show the payload (the data) if there is any
    if Raw in packet:
        data = packet[Raw].load
        text = data.decode(errors="replace")[:100]   # first 100 characters
        print(f"Payload     : {text}")


# ---------------- Main program ----------------
print("Capturing 20 packets... (press Ctrl+C to stop early)")

try:
    sniff(prn=show_packet, count=20, store=False)
except KeyboardInterrupt:
    pass

# Summary at the end
print("\n" + "=" * 40)
print("SUMMARY")
print(f"Total packets: {packet_number}")
for name, number in protocol_count.items():
    print(f"  {name}: {number}")