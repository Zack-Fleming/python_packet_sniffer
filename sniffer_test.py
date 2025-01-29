import socket
import struct
import textwrap
import utils
import sys

# main loop
def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        # capture a packet
        data_raw, addr = connection.recvfrom(65535)

        # unpack the Ethernet Frame
        dest_mac, src_mac, eth_type, ip_data = unpack_frame(data_raw)
        print('\n\nEthernet Frame Data:')
        print('\tDestination: {}, \n\tSource: {}, \n\tEtherType: \n\t\t(DEC): {}, \n\t\t(BIN): {}, \n\t\t(HEX): {}, \n\t\t(STR): {}'.format(dest_mac, src_mac, eth_type, format(eth_type, '#018b'), '0x' + '{:04x}'.format(eth_type).upper(), utils.get_eth_str('0x' + '{:04x}'.format(eth_type).upper())))

        # get the version of the packet
        version = get_packet_version(ip_data)
        ver_desc, ver_status, code = utils.get_ip_vers(version)
        print('\tIP Packet Data:')
        print('\t\tVersion: \n\t\t\t(DEC): {}, \n\t\t\t(BIN): {}, \n\t\t\t(HEX): {}\n\t\t\tDescription: {},\n\t\t\tStatus: {}'.format(version, format(version, '#06b'), '0x' + '{:02x}'.format(version).upper(), ver_desc, ver_status))
        
        # check if the packet is IPv4 or IPv6
        if version == 4:
            ihl, tos, tot_len, ID, flags, frag_offl = unpack_IPv4(ip_data)
            print('\t\tIHL: {}bytes\n\t\tType of Service: {}\n\t\tTotal Length: {}\n\t\tIdentification: {}\n\t\tFlags: {}\n\t\tFragment Offset: {}'.format(ihl, tos, tot_len, ID, flags, ''.join(format(ord(frag_offl), '08b'))))


# unpacking the ethernet frame
def unpack_frame(data):
    dest, src, eth_protocol = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(dest), format_mac(src), eth_protocol, data[14:]


# format the MAC address
def format_mac(mac):
    mac_str = map('{:02x}'.format, mac)
    return ':'.join(mac_str).upper()


# get the version of the packet
def get_packet_version(data):
    return data[0] >> 4


# unpack the IP packet data
def unpack_IPv4(data):
    IHL = (data[0] & 15) * 4
    flags = data[6] >> 5
    frag = data[6:7]

    return IHL, data[1], data[2:3], data[4:5], format(flags, '#05b'), frag












main()