from scapy.all import *
from utility.sniffer_data_sets import *


# main loop
def main():
    # create a socket connection
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    # create a list of packets
    packets = []

    try:
        while True:
            # capture a packet
            data_raw, addr = connection.recvfrom(65535)
            packets.append(data_raw)

            # unpack the Ethernet Frame
            dest_mac, src_mac, eth_type, packet_data = unpack_frame(data_raw)

            if sum(src_mac) != 0 or sum(dest_mac) != 0:
                # print time and packet size
                print('\n\nPacket Info:\n\tLength: {}\n\tTimestamp: {}'.format(len(data_raw), time.time()))
                # print the Ethernet frame data
                print('Ethernet Frame Data:')
                print('\tSource MAC: {}\n\tDestination MAC: {}'.format(format_mac(src_mac), format_mac(dest_mac)))
                print('\tEtherType:\n\t\t(DEC): {}\n\t\t(BIN): {}\n\t\t(HEX): {}\n\t\t(STR): {}'.format(eth_type, format(eth_type, '#018b'), '0x' + '{:04x}'.format(eth_type).upper(), get_eth_str('0x' + '{:04x}'.format(eth_type).upper())))

                # unpack ARP packet
                if eth_type == 2054:
                    hw_type, proto_type, hw_len, p_len, op_code, send_hw, send_proto, target_hw, target_proto = unpack_arp(packet_data)
                    print('\tAddress Resolution Protocol Packet:')
                    print('\t\tHardware Type: {}\n\t\tProtocol Type: {}'.format(hw_type, proto_type))
                    print('\t\tHardware Length: {}\n\t\tProtocol Length: {}'.format(hw_len, p_len))
                    print('\t\tOperation Code: {} ({})'.format(op_code, 'Request' if op_code == 1 else 'Reply'))
                    print('\t\tSender Hardware Address: {}\n\t\tSender Protocol Address: {}'.format(format_mac(send_hw), format_ip(send_proto)))
                    print('\t\tTarget Hardware Address: {}\n\t\tTarget Protocol Address: {}'.format(format_mac(target_hw), format_ip(target_proto)))
                # unpack IPv6 packet
                elif eth_type == 34525:
                    version, traffic_class, flow_label, payload_length, next_header, hop_limit, src, dst, ipv6_payload = unpack_ipv6(packet_data)
                    print('\tInternet Protocol Version 6 Packet:')
                    print('\t\tVersion: {}\n\t\tTraffic Class: {}'.format(version, traffic_class))
                    print('\t\tFlow Label: {}\n\t\tPayload Length: {}'.format(flow_label, payload_length))
                    print('\t\tNext Header: {}\n\t\tHop Limit: {}'.format(next_header, hop_limit))
                    print('\t\tSource Address: {}\n\t\tDestination Address: {}'.format(form_ipv6_addr(src), form_ipv6_addr(dst)))
                # unpack IPv4 packet
                elif eth_type == 2048:
                    version, ihl, dscp, ecn, total_length, identification, flags, frag_off, ttl, protocol, head_check, src, dst, ipv4_payload = unpack_ipv4(packet_data)
                    proto_abbr, proto_name, proto_ref, code = get_ip_protocol('0x' + '{:02x}'.format(protocol).upper())
                    print('\tInternet Protocol version 4 Packet:')
                    print('\t\tVersion: {}\n\t\tInternet Header Length: {}'.format(version, ihl))
                    print('\t\tDifferentiated Services Code Point (DSCP): {}\n\t\tExplicit Congestion Notification (ESC): {}'.format(dscp, ecn))
                    print('\t\tTotal Length: {}\n\t\tIdentification: {}'.format(total_length, identification))
                    print('\t\tFlags: {}\n\t\t\tReserved bit (R): {}\n\t\t\tDon\'t Fragment bit (DF): {}\n\t\t\tMore Fragments bit (MF): {}'.format(format(flags, '#05b'), (flags >> 2) & 1, (flags >> 1) & 1, flags & 1))
                    print('\t\tFragment Offset: {}\n\t\tTime To Live: {}'.format(frag_off, ttl))
                    print('\t\tProtocol: {}\n\t\t\tAbbreviation: {}\n\t\t\tFull Name: {}\n\t\tReferences: {}'.format(protocol, proto_abbr, proto_name, proto_ref))
                    print('\t\tHeader Checksum: {}\n\t\tSource IP: {}\n\t\tDestination IP: {}'.format(head_check, format_ip(src), format_ip(dst)))

                    # if protocol is 1 (0x01) - ICMP
                    if protocol == 1:
                        type_code, subtype_code, checksum, icmp_data = unpack_icmp(ipv4_payload)
                        icmp_type, icmp_subtype, icmp_type_status, ret_code = get_icmp_type(str(type_code), str(subtype_code))
                        print('\t\tInternet Control Message Protocol (ICMP) Packet:')
                        print('\t\t\tType: {} ({}) ({})'.format(type_code, icmp_type, icmp_type_status))
                        print('\t\t\tSubtype: {} ({})'.format(subtype_code, icmp_subtype))
                    # if protocol is 6 (0x06) - TCP/IP
                    elif protocol == 6:
                        src_port, dst_port, sequence_num, ack_num, data_offset, reserved, flags, window, checksum, upointer, tcp_data = unpack_tcp(ipv4_payload)
                        print('\t\tTransmission Control Protocol Packet:')
                        print('\t\t\tSource Port: {}\n\t\t\tDestination Port: {}'.format(src_port, dst_port))
                        print('\t\t\tSequence Number: {}\n\t\t\tAckknowledge Number: {}'.format(sequence_num, ack_num))
                        print('\t\t\tData Offset: {}\n\t\t\tReserved Bits: {}'.format(data_offset, reserved))
                        print('\t\t\tFlags: {}\n\t\t\tSliding Window: {}'.format(flags, window))
                        print('\t\t\tChecksum: {}\n\t\t\tUrgent Pointer: {}'.format(checksum, upointer))
                    # UDP
                    elif protocol == 17:
                        src_port, dst_port, length, checksum, udp_data = unpack_udp(ipv4_payload)
                        print('\t\tUser Datagram Protocol Packet:')
                        print('\t\t\tSource Port: {}\n\t\t\tDestination Port: {} ()'.format(src_port, dst_port))
                        print('\t\t\tLength: {}\n\t\t\tChecksum: {}'.format(length, checksum))
    # Use CTRL + C as a 'stop capture' and save packets to file
    except KeyboardInterrupt:
        # get current datetime for filename
        date_time = datetime.now()
        formatted_datetime = date_time.strftime("%Y-%m-%d_%H:%M:%S")
        # create the pcap writer object
        pcap_writer = PcapWriter('capture_' + formatted_datetime + '.pcap', append=True, sync=True)

        print('writing packets to: capture_{}.pcap'.format(formatted_datetime))

        # write the packets to the file
        for packet in packets:
            pcap_writer.write(packet)

        pcap_writer.close() # close the writer
        print('packets written to file')


# unpacking the ethernet frame
def unpack_frame(data):
    dest, src, eth_protocol = struct.unpack('! 6s 6s H', data[:14])
    return dest, src, eth_protocol, data[14:]

# unpack an ARP packet
def unpack_arp(data):
    hw_type, proto_type, hw_len, p_len, op_code, send_hw, send_proto, target_hw, target_proto = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
    return hw_type, proto_type, hw_len, p_len, op_code, send_hw, send_proto, target_hw, target_proto

# unpack an IPv6 Packet
def unpack_ipv6(data):
    ver = data[0] >> 4
    first_row, plen, nxt, hop = struct.unpack('! I H B B', data[:8])
    src = struct.unpack('! 8H', data[8:24])
    dst = struct.unpack('! 8H', data[24:40])
    traf = (first_row >> 20) & 255
    flow = first_row & 1048575

    return ver, traf, flow, plen, nxt, hop, src, dst, data[40:]

# unpack ipv4 packet
def unpack_ipv4(data):
    ver_ihl, tos, total, id, flag_offset, ttl, proto, check, src, dst = struct.unpack('! B B H H H B B H 4s 4s', data[:20])
    ver = ver_ihl >> 4
    ihl = (ver_ihl & 15) * 4
    dscp = tos >> 2
    ecn = tos & 3
    flags = flag_offset >> 13
    offset = flag_offset & 8191

    return ver, ihl, dscp, ecn, total, id, flags, offset, ttl, proto, check, src, dst, data[20:]

# unpack ICMP packet (inside IPv4)
def unpack_icmp(data):
    ty, co, check = struct.unpack('! B B H', data[:4])
    return ty, co, check, data[4:]

# unpack tcp packet
def unpack_tcp(data):
    src, dst, seq, ack, off_res, flags, win, csum, upnt = struct.unpack('! H H I I B B H H H', data[:20])
    off = off_res >> 4
    res = off_res & 15
    return src, dst, seq, ack, off, res, flags, win, csum, upnt, data[20:]

# unpack udp packet
def unpack_udp(data):
    src, dst, leng, csum = struct.unpack('! H H H H', data[:8])
    return src, dst, leng, csum, data[8:]


# format the MAC address
# mac - byte array
def format_mac(mac):
    mac_str = map('{:02x}'.format, mac)
    return ':'.join(mac_str).upper()

# format an IP address
# IP - byte array
def format_ip(ip):
    return '.'.join(str(byte) for byte in ip)

# format ipv6 ip address
def form_ipv6_addr(addr):
    ip_str = map('{:04x}'.format, addr)
    return ':'.join(ip_str).upper()



main()