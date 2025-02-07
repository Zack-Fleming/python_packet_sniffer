from pylibpcap import get_iface_list
from pylibpcap.pcap import sniff

# print the list of available interfaces
print(get_iface_list())

# capture a packet
