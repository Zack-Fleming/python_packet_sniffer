from scapy.all import *
import socket
import time

# create a connection
connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
# list of packets for pcap file
packets = []
# start time for timestamp
start_time = time.time()

for i in range(20):
    # calculate elapsed time
    end_time = time.time()
    # print time packet was captured
    print("packet" + str(i) + " at " + str((end_time - start_time)))
    # receive packet
    packet, addr = connection.recvfrom(65535)
    # add packet to list
    packets.append(packet)

# have user give a filename
file_name = input("Filename of pcap: ")

# create the writer object
pcap_writer = PcapWriter(file_name, append=True, sync=True)

# loop through list and write each packet to file
for packet in packets:
    pcap_writer.write(packet)

#closr file writer
pcap_writer.close()