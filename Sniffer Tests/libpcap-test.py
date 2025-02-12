from pylibpcap import get_iface_list
from pylibpcap.base import LibpcapError
from pylibpcap.pcap import Sniff

# print the list of available interfaces
print(get_iface_list())

# capture a packet
sniff_object = None

try:
    sniff_object = Sniff("wlan0", count=-1, promisc=1, out_file="capture.pcap")

    for plen, t, buf in sniff_object.capture():
        print("\n\n[+]: Payload len=", plen)
        print("[+]: Time", t)
        print("[+]: Payload", buf)
except KeyboardInterrupt:
    pass
except LibpcapError as e:
    print(e)


if sniff_object is not None:
    stats = sniff_object.stats()
    print(stats.capture_cnt, " packets captured")
    print(stats.ps_recv, " packets received by filter")
    print(stats.ps_drop, "  packets dropped by kernel")
    print(stats.ps_ifdrop, "  packets dropped by iface")
    sniff_object.capture()