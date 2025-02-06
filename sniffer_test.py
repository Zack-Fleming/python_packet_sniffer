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
        dest_mac, src_mac, eth_type, packet_data = unpack_frame(data_raw)

        if sum(src_mac) != 0 or sum(dest_mac) != 0:
            print('\n\nEthernet Frame Data:')
            print('\tDestination: {}, \n\tSource: {}, \n\tEtherType: \n\t\t(DEC): {}, \n\t\t(BIN): {}, \n\t\t(HEX): {}, \n\t\t(STR): {}'.format(format_mac(dest_mac), format_mac(src_mac), eth_type, format(eth_type, '#018b'), '0x' + '{:04x}'.format(eth_type).upper(), utils.get_eth_str('0x' + '{:04x}'.format(eth_type).upper())))

            # unpack ARP packet
            if eth_type == 2054:
                hw_type, proto_type, hw_len, p_len, op_code, send_hw, send_proto, target_hw, target_proto = unpack_arp(packet_data)
                print('\tAddress Resolution Protocol Packet:')
                print('\t\tHardware Type: {}\n\t\tProtocol: {}\n\t\tHardware Length: {}\n\t\tProtocol Length: {}\n\t\tOp Code: {}\n\t\tSender Hardware Address: {}\n\t\tSender Protocol Address: {}\n\t\tTarget Hardware Address: {}\n\t\tTarget Protocol Address: {}'.format(hw_type, proto_type, hw_len, p_len, op_code, format_mac(send_hw), format_IP(send_proto), format_mac(target_hw), format_IP(target_proto)))



            # # get the version of the packet
            # version = get_packet_version(packet_data)
            # ver_desc, ver_status, code = utils.get_ip_vers(version)
            # print('\tIP Packet Data:')
            # print('\t\tVersion: \n\t\t\t(DEC): {}, \n\t\t\t(BIN): {}, \n\t\t\t(HEX): {}\n\t\t\tDescription: {},\n\t\t\tStatus: {}'.format(version, format(version, '#06b'), '0x' + '{:02x}'.format(version).upper(), ver_desc, ver_status))
            #
            # # check if the packet is IPv4 or IPv6
            # if version == 4:
            #     ihl, tos, tot_len, ID, flags, frag_off = unpack_IPv4(packet_data)
            #     print('\t\tIHL: {}bytes\n\t\tType of Service: {}\n\t\tTotal Length: {}\n\t\tIdentification: {}\n\t\tFlags: {}\n\t\tFragment Offset: {}'.format(ihl, tos, ''.join(format(ord(tot_len), '016b')), ''.join(format(ord(ID), '016b')), flags,''.join(format(ord(frag_off), '08b'))))


# unpacking the ethernet frame
def unpack_frame(data):
    dest, src, eth_protocol = struct.unpack('! 6s 6s H', data[:14])
    return dest, src, eth_protocol, data[14:]


# format the MAC address
# mac - byte array
def format_mac(mac):
    mac_str = map('{:02x}'.format, mac)
    return ':'.join(mac_str).upper()

# format an IP address
# IP - byte array
def format_IP(ip):
    return '.'.join(str(byte) for byte in ip)


# unpack an ARP packet
def unpack_arp(data):
    hw_type, proto_type, hw_len, p_len, op_code, send_hw, send_proto, target_hw, target_proto = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
    return hw_type, proto_type, hw_len, p_len, op_code, send_hw, send_proto, target_hw, target_proto


# get the version of the packet
def get_packet_version(data):
    return data[0] >> 4


# unpack the IP packet data
# return order : IHL, DSCP, tot_len, ID, flags, frag_off
def unpack_IPv4(data):
    IHL = (data[0] & 15) * 4
    flags = data[6] >> 5
    frag = data[6:7]

    return IHL, data[1], data[2:3], data[4:5], format(flags, '#05b'), frag












main()