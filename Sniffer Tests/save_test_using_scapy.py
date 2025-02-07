import socket
from scapy.all import *
from scapy.layers.inet import IP

# create a connection
connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
# make a list of packets
packets = []

# capture some packets
for i in range(10):
    print(str(i))
    # capture a packet
    packet = connection.recv(65535)
    # append packet to list
    packets.append(packet)

# create the pcap writer ocject
pcap_writer = PcapWriter("test.pcap", append=True, sync=True)

# enumerate the packets list and write them to the file
for packet in packets:
    pcap_writer.write(packet)

pcap_writer.close() # close the file