from scapy.all import *
from sniffer_data_sets import *


def unpack_frame(data: bytes):
    """
    Unpacks an Ethernet Frame, using struct.

    Args:
        data: bytes - data of the ethernet frame

    Returns:
        destination MAC as a char[6],
        source MAC as a char[6],
        ethernet protocol as an int16,
        encapsulated packet data as bytes[]

    Raises:
        None
    """
    dest, src, eth_protocol = struct.unpack('! 6s 6s H', data[:14])
    return dest, src, eth_protocol, data[14:]


def unpack_arp(data: bytes):
    """
    Unpacks an ARP packet using struct.

    Args:
        data: bytes - data of the ARP packet

    Returns:
        hardware type as an int16,
        protocol type as an int16,
        hardware length as an int8,
        protocol length as an int8,
        operation code as an int16,
        sender hardware address (MAC) as a char[6],
        sender protocol address (IP) as a char[4],
        target hardware address (MAC) as a char[6],
        target protocol address (IP) as a char[4],
        ARP data as bytes[]

    Raises:
        None

    """
    hw_type, proto_type, hw_len, p_len, op_code, send_hw, send_proto, target_hw, target_proto = struct.unpack(
        '! H H B B H 6s 4s 6s 4s', data[:28])
    return hw_type, proto_type, hw_len, p_len, op_code, send_hw, send_proto, target_hw, target_proto


def unpack_ipv6(data: bytes):
    """
    Unpacks an IPv6 packet using struct.

    Args:
        data: bytes - data of the IPv6 packet

    Returns:
        version as an int8,
        traffic class as an int32,
        flow label as an int32,
        payload length as an int16,
        next header as an int8,
        hop limit as an int8,
        source address as an int16[8],
        destination address as an int16[8],
        encapsulated payload data as bytes[]

    Raises:
        None
    """
    ver = data[0] >> 4
    first_row, plen, nxt, hop = struct.unpack('! I H B B', data[:8])
    src = struct.unpack('! 8H', data[8:24])
    dst = struct.unpack('! 8H', data[24:40])
    traf = (first_row >> 20) & 255
    flow = first_row & 1048575

    return ver, traf, flow, plen, nxt, hop, src, dst, data[40:]


def unpack_ipv4(data: bytes):
    """
    Unpacks an IPv4 header using struct

    Args:
        data: bytes - data of the IPv4 packet

    Returns:
        version as an int8,
        header length as an int8,
        DECP as an int8,
        ECN as an int8,
        total length as an int16,
        identification as an int16,
        flags as an int16 (first three bits are the flags, 13 are zeros),
        fragment offset as an int16,
        TTL as an int8,
        protocol as an int8,
        header checksum as an int16,
        source address as a char[4],
        destination address as a char[4],
        payload as bytes[]


    Raises:
        None
    """
    ver_ihl, tos, total, id, flag_offset, ttl, proto, check, src, dst = struct.unpack('! B B H H H B B H 4s 4s', data[:20])
    ver = ver_ihl >> 4
    ihl = (ver_ihl & 15) * 4
    dscp = tos >> 2
    ecn = tos & 3
    flags = flag_offset >> 13
    offset = flag_offset & 8191

    return ver, ihl, dscp, ecn, total, id, flags, offset, ttl, proto, check, src, dst, data[20:]


def unpack_icmp(data: bytes):
    """
    Unpacks an ICMP packet, using struct.

    Args:
        data: bytes - data of the ICMP packet

    Returns:
        type as an int8,
        code as an int8,
        checksum as an int16,
        rest of header as bytes[4]

    Raises:
        None
    """
    ty, co, check = struct.unpack('! B B H', data[:4])
    return ty, co, check, data[4:]


def unpack_tcp(data: bytes):
    """
    Unpacks a TCP packet using struct.

    Args:
        data: bytes - data of the TCP packet

    Returns:
        source port as an int16,
        destination port as an int16,
        Sequence number as an int32,
        acknowledgment number as an int32,
        data offset as an int8,
        reserved as an int8,
        flags as an int8,
        window as an int16,
        checksum as an int16,
        urgent pointer as an int16,
        rest of the packet as a bytes[]

    Raises:
        None
    """
    src, dst, seq, ack, off_res, flags, win, csum, upnt = struct.unpack('! H H I I B B H H H', data[:20])
    off = off_res >> 4
    res = off_res & 15
    return src, dst, seq, ack, off, res, flags, win, csum, upnt, data[20:]


def unpack_udp(data: bytes):
    """
    Unpacks UDP packet, using struct.

    Args:
        data: bytes - data of the UDP packet

    Returns:
        source port as an int16,
        destination port as an int16,
        payload length as an int16,
        packet checksum as an int16,
        payload as bytes[]

    Raises:
        None
    """
    src, dst, leng, csum = struct.unpack('! H H H H', data[:8])
    return src, dst, leng, csum, data[8:]


def format_mac(mac: bytes):
    """
    Formats raw MAC data into string.

    Args:
        mac: bytes - data of the MAC address.

    Returns:
        formatted MAC address as a LiteralString or str

    Raises:
        None
    """
    mac_str = map('{:02x}'.format, mac)
    return ':'.join(mac_str).upper()


def format_ip(ip: bytes):
    """
    Formats raw IPv4 address data into formatted strings.

    Args:
        ip: bytes - array of bytes representing the address

    Returns:
        formatted IPv4 address as a str

    Raises:
        None
    """
    return '.'.join(str(byte) for byte in ip)


def form_ipv6_addr(addr: bytes):
    """
    Formats raw IPv6 address data into a formatted string.

    Args:
        addr: bytes - raw data of the address

    Returns:
        formatted IPv6 address as a LiteralString or str

    Raises:
        None
    """
    ip_str = map('{:04x}'.format, addr)
    return ':'.join(ip_str).upper()