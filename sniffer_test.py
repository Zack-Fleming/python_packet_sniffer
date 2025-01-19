import socket
import struct
import textwrap
import utils

# main loop
def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        # capture a packet
        data_raw, addr = connection.recvfrom(65535)

        # unpack the Ethernet Frame
        dest_mac, src_mac, eth_type, ip_data = unpack_frame(data_raw)
        print('\n\nEthernet Frame Data:')
        print('\tDestination: {}, \n\tSource: {}, \n\tEtherType: \n\t\t(DEC): {}, \n\t\t(HEX): {}, \n\t\t(STR): {}'.format(dest_mac, src_mac, eth_type, '0x{:04x}'.format(eth_type).upper(), utils.get_eth_str('0x' + '{:04x}'.format(eth_type).upper())))

        # unpack the IP Packet
        ver, ihl, serv_type = unpack_IP(ip_data)
        print('\tIP Packet Data:')
        print('\t\tVersion: {}\n\t\tIHL: {}\n\t\tService Type: {}'.format(ver, ihl, serv_type))


# unpacking the ethernet frame
def unpack_frame(data):
    dest, src, eth_protocol = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(dest), format_mac(src), eth_protocol, data[14:]


# format the MAC address
def format_mac(mac):
    mac_str = map('{:02x}'.format, mac)
    return ':'.join(mac_str).upper()


# unpack the IP packet data
def unpack_IP(data):
    version_IHL = data[0]
    version = version_IHL >> 4
    IHL = (version_IHL & 15) * 4
    return version, IHL, data[1]












main()