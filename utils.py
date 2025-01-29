eth_dict= {
    "0x0800": "Internet Protocol Version 4 (IPv4)",
    "0x0806": "Address Resolution Protocol (ARP)",
    "0x0842": "Wake-on-LAN",
    "0x22EA": "Stream Reservation Protocol (SRP)",
    "0x22F0": "Audio Video Transport Protocol (AVTP)",
    "0x22F3": "IETF TRILL Protocol",
    "0x6002": "DEC MOP RC",
    "0x6003": "DECnet Phase IV, DNA Routing",
    "0x6004": "DEC LAT",
    "0x8035": "Reverse Address Resolution Protocol (RARP)",
    "0x809B": "AppleTalk (EtherTalk)",
    "0x80D5": "LLC PDU",
    "0x80F3": "AppleTalk Address Resolution Protocol (AARP)",
    "0x8100": "VLAN-tagged frame (802.1Q) & Shortest Path Bridging (IEEE802.aq w/ NNI)",
    "0x8102": "Simple Loop Prevention Protocol (SLPP)",
    "0x8103": "Virtual Link Aggregation Control Protocol (VLACP)",
    "0x8137": "IPX",
    "0x8204": "QNX Qnet",
    "0x86DD": "Internet Protocol Version 6 (IPv6)",
    "0x8808": "Ethernet flow control",
    "0x8809": "Ethernet Slow Protocols (i.e. LCAP)",
    "0x8819": "CobraNet",
    "0x8847": "MPLS unicast",
    "0x8848": "MPLS multicast",
    "0x8863": "PPPoE Discovery Stage",
    "0x8864": "PPPoE session Stage",
    "0x887B": "HomePlug 1.0 MME",
    "0x888B": "EAP over LAN (IEEE 802.1X)",
    "0x8892": "PROFINET Protocol",
    "0x889A": "HyperSCSI (SCSIoE",
    "0x88A2": "ATA over Ethernet (ATAoE)",
    "0x88A4": "EtherCAT Protocol",
    "0x88A8": "Service VLAN tag identifier (S-Tag)",
    "0x88AB": "Ethernet Powerlink",
    "0x88B8": "Generic Object Oriented Substation Event (GOOSE)",
    "0x88B9": "GSE (Generic Substation Event) Management Services",
    "0x88BA": "Sampled Value Transmission",
    "0x88BF": "MikroTik RoMON (unofficial)",
    "0x88CC": "Link Layer Discovery Protocol (LLDP)",
    "0x88CD": "SERCOS III",
    "0x88E1": "HomePlug Green PHY",
    "0x88E3": "Media Redundancy Protocol (IEC62439-2)",
    "0x88E5": "IEEE 802.1AE Mac Security (MACSec)",
    "0x88E7": "Provider Backbone Bridges (PBB, IEEE 802.1ah)",
    "0x88F7": "Precision Time Protocol (PTP) over IEEE 802.3 Ethernet",
    "0x88F8": "Network Controller Sideband Interface (NC-SI)",
    "0x88FB": "Parallel Redundancy Protocol (PRP)",
    "0x8902": "IEEE 802.1ag Connectivity Fault Management Protocol (CFM)",
    "0x8906": "Fibre Channel over Ethernet (FCoE)",
    "0x8914": "FCoE Initialization Protocol",
    "0x8915": "RDMA over Converged Ethernet (RoCE)",
    "0x891D": "TTEthernet Protocol Control Frame (TTE)",
    "0x893A": "1905.1 IEEE Protocol",
    "0x892F": "High-availability Seamless Redundancy (HSR)",
    "0x9000": "Ethernet Configuration Protocol",
    "0xF1C1": "Redundancy Tag (IEEE 802.1CB)"
}

ip_prot_dict = {
    "0x00": {
        "abbreviation": "HOPOPT",
        "protocol": "IPv6 Hop=by=Hop Option",
        "references": "RFC 8200"
    },
    "0x01": {
        "abbreviation": "ICMP",
        "protocol": "Internet Control Message Protocol",
        "references": "RFC 792"
    },
    "0x02": {
        "abbreviation": "IGMP",
        "protocol": "Internet Group Management Protocol",
        "references": "RFC 1112"
    },
    "0x03": {
        "abbreviation": "GGP",
        "protocol": "Gateway-to-Gateway Protocol",
        "references": "RFC 823"
    },
    "0x04": {
        "abbreviation": "IP-in-IP",
        "protocol": "IP in IP (encapsulation)",
        "references": "RFC 2003"
    },
    "0x05": {
        "abbreviation": "ST",
        "protocol": "Internet Stream Protocol",
        "references": "RFC 1190, RFC 1819"
    },
    "0x06": {
        "abbreviation": "TCP",
        "protocol": "Transmission Control Protocol",
        "references": "RFC 793"
    },
    "0x07": {
        "abbreviation": "CBT",
        "protocol": "Core-Based Trees",
        "references": "RFC 2189"
    },
    "0x08": {
        "abbreviation": "EGP",
        "protocol": "Exterior Gateway Protocol",
        "references": "RFC 888"
    },
    "0x09": {
        "abbreviation": "IGP",
        "protocol": "Interior Gateway Protocol (ex. IGRP)",
        "references": "n/a"
    },
    "0x0A": {
        "abbreviation": "BBN-RCC-MON",
        "protocol": "BBN RCC Monitoring",
        "references": "n/a"
    },
    "0x0B": {
        "abbreviation": "NVP-II",
        "protocol": "Network Voice Protocol",
        "references": "RFC 741"
    },
    "0x0C": {
        "abbreviation": "PUP",
        "protocol": "Xerox PUP",
        "references": "n/a"
    },
    "0x0D": {
        "abbreviation": "ARGUS",
        "protocol": "ARGUS",
        "references": "n/a"
    },
    "0x0E": {
        "abbreviation": "EMCON",
        "protocol": "EMCON",
        "references": "n/a"
    },
    "0x0F": {
        "abbreviation": "XNET",
        "protocol": "Cross Net Debugger",
        "references": "IEN 158"
    },
    "0x10": {
        "abbreviation": "CHAOS",
        "protocol": "Chaos",
        "references": "n/a"
    },
    "0x11": {
        "abbreviation": "UDP",
        "protocol": "User Datagram Protocol",
        "references": "RFC 768"
    },
    "0x12": {
        "abbreviation": "MUX",
        "protocol": "Multiplexing",
        "references": "IEN 90"
    },
    "0x13": {
        "abbreviation": "DCN-MEAS",
        "protocol": "DCN Measurement Subsystem",
        "references": "n/a"
    },
    "0x14": {
        "abbreviation": "HMP",
        "protocol": "Host Monitoring Protocol",
        "references": "RFC 869"
    },
    "0x15": {
        "abbreviation": "PRM",
        "protocol": "Packet Radio Measurement",
        "references": "n/a"
    },
    "0x16": {
        "abbreviation": "XNS-IDP",
        "protocol": "XEROX NS IDP",
        "references": "n/a"
    },
    "0x17": {
        "abbreviation": "TRUNK-1",
        "protocol": "Trunk-1",
        "references": "n/a"
    },
    "0x18": {
        "abbreviation": "TRUNK-2",
        "protocol": "Trunk-2",
        "references": "n/a"
    },
    "0x19": {
        "abbreviation": "LEAF-1",
        "protocol": "Leaf-1",
        "references": "n/a"
    },
    "0x1A": {
        "abbreviation": "LEAF-2",
        "protocol": "Leaf-2",
        "references": "n/a"
    },
    "0x1B": {
        "abbreviation": "RDP",
        "protocol": "Reliable Data Protocol",
        "references": "RFC 908"
    },
    "0x1C": {
        "abbreviation": "IRTP",
        "protocol": "Internet Reliable Transaction Protocol",
        "references": "RFC 938"
    },
    "0x1D": {
        "abbreviation": "ISO-TP4",
        "protocol": "ISO Transport Protocol Class 4",
        "references": "RFC 905"
    },
    "0x1E": {
        "abbreviation": "NETBLT",
        "protocol": "Bulk Data Transfer Protocol",
        "references": "RFC 998"
    },
    "0x1F": {
        "abbreviation": "MFE-NSP",
        "protocol": "MFE Network Services Protocol",
        "references": "n/a"
    },
    "0x20": {
        "abbreviation": "MERIT-INP",
        "protocol": "MERIT Internodal Protocol",
        "references": "n/a"
    },
    "0x21": {
        "abbreviation": "DCCP",
        "protocol": "Datagram Congestion Control Protocol",
        "references": "RFC 4340"
    },
    "0x22": {
        "abbreviation": "3PC",
        "protocol": "Third Party Connect Protocol",
        "references": "n/a"
    },
    "0x23": {
        "abbreviation": "IDPR",
        "protocol": "Inter-Domain Policy Routing Protocol",
        "references": "RFC 1479"
    },
    "0x24": {
        "abbreviation": "XTP",
        "protocol": "Xpress Transport Protocol",
        "references": "n/a"
    },
    "0x25": {
        "abbreviation": "DDP",
        "protocol": "Datagram Delivery Protocol",
        "references": "n/a"
    },
    "0x26": {
        "abbreviation": "IDPR+CMTP",
        "protocol": "IDPR Control Message Transport Protocol",
        "references": "n/a"
    },
    "0x27": {
        "abbreviation": "TP++",
        "protocol": "TP++ Transport Protocol",
        "references": "n/a"
    },
    "0x28": {
        "abbreviation": "IL",
        "protocol": "Internet Link Transport Protocol",
        "references": "n/a"
    },
    "0x29": {
        "abbreviation": "IPv6",
        "protocol": "IPv6 Encapsulation",
        "references": "RFC 2473"
    },
    "0x2A": {
        "abbreviation": "SDRP",
        "protocol": "Source Demand Routing Protocol",
        "references": "RFC 1940"
    },
    "0x2B": {
        "abbreviation": "IPv6-Route",
        "protocol": "Routing Header for IPv6",
        "references": "RFC 8200"
    },
    "0x2C": {
        "abbreviation": "IPv6-Frag",
        "protocol": "Fragment Header for IPv6",
        "references": "RFC 8200"
    },
    "0x2D": {
        "abbreviation": "IDRP",
        "protocol": "Inter-Domain Routing Protocol",
        "references": "n/a"
    },
    "0x2E": {
        "abbreviation": "RSVP",
        "protocol": "Resource Reservation Protocol",
        "references": "RFC 2205"
    },
    "0x2F": {
        "abbreviation": "GRE",
        "protocol": "Generic Routing Encapsulation",
        "references": "RFC 2784, RFC 2890"
    },
    "0x30": {
        "abbreviation": "DSR",
        "protocol": "Dynamic Source Routing Protocol",
        "references": "RFC 4728"
    },
    "0x31": {
        "abbreviation": "BNA",
        "protocol": "Burroughs Network Architecture",
        "references": "n/a"
    },
    "0x32": {
        "abbreviation": "ESP",
        "protocol": "Encapsulating Security Protocol",
        "references": "RFC 4303"
    },
    "0x33": {
        "abbreviation": "AH",
        "protocol": "Authentication Header",
        "references": "RFC 4302"
    },
    "0x34": {
        "abbreviation": "I-NLSP",
        "protocol": "Integrated Net Layer Security Protocol",
        "references": "TUBA"
    },
    "0x35": {
        "abbreviation": "SwIPe",
        "protocol": "SwIPe IP Security Protocol",
        "references": "RFC 5237"
    },
    "0x36": {
        "abbreviation": "NARP",
        "protocol": "NBMA Address Resolution Protocol",
        "references": "RFC 1735"
    },
    "0x37": {
        "abbreviation": "MOBILE",
        "protocol": "IP Mobility (Min Encap)",
        "references": "RFC 2004"
    },
    "0x38": {
        "abbreviation": "TLSP",
        "protocol": "Transport Layer Security Protocol",
        "references": "n/a"
    },
    "0x39": {
        "abbreviation": "SKIP",
        "protocol": "Simple Key-Management for Internet Protocol",
        "references": "RFC 2356"
    },
    "0x3A": {
        "abbreviation": "IPv6-ICMP",
        "protocol": "ICMP for IPv6",
        "references": "RFC 4443, RFC 4884"
    },
    "0x3B": {
        "abbreviation": "IPv6-NoNxt",
        "protocol": "No Next Header for IPv6",
        "references": "RFC 8200"
    },
    "0x3C": {
        "abbreviation": "IPv6-Opts",
        "protocol": "Destination Options for IPv6",
        "references": "RFC 8200"
    },
    "0x3D": {
        "abbreviation": "n/a",
        "protocol": "Any Host Internal Protocol",
        "references": "n/a"
    },
    "0x3E": {
        "abbreviation": "CFTP",
        "protocol": "Compressed File Transfer Protocol",
        "references": "n/a"
    },
    "0x3F": {
        "abbreviation": "n/a",
        "protocol": "Any Local Network",
        "references": "n/a"
    },
    "0x40": {
        "abbreviation": "SAT-EXPAK",
        "protocol": "SATNET and Backroom EXPAK",
        "references": "n/a"
    },
    "0x41": {
        "abbreviation": "KRYPTOLAN",
        "protocol": "Kryptolan",
        "references": "n/a"
    },
    "0x42": {
        "abbreviation": "RVD",
        "protocol": "MIT Remote Virtual Disk Protocol",
        "references": "n/a"
    },
    "0x43": {
        "abbreviation": "IPPC",
        "protocol": "Internet Pluribus Packet Core",
        "references": "n/a"
    },
    "0x44": {
        "abbreviation": "n/a",
        "protocol": "Any Distributed File System",
        "references": "n/a"
    },
    "0x45": {
        "abbreviation": "SAT-MON",
        "protocol": "SATNET Monitoring",
        "references": "n/a"
    },
    "0x46": {
        "abbreviation": "VISA",
        "protocol": "VISA Protocol",
        "references": "n/a"
    },
    "0x47": {
        "abbreviation": "IPCU",
        "protocol": "Internet Packet Core Utility",
        "references": "n/a"
    },
    "0x48": {
        "abbreviation": "CPNX",
        "protocol": "Computer Protocol Network Executive",
        "references": "n/a"
    },
    "0x49": {
        "abbreviation": "CPHB",
        "protocol": "Computer Protocol Heart Beat",
        "references": "n/a"
    },
    "0x4A": {
        "abbreviation": "WSN",
        "protocol": "Wang Span Network",
        "references": "n/a"
    },
    "0x4B": {
        "abbreviation": "PVP",
        "protocol": "Packet Video Protocol",
        "references": "n/a"
    },
    "0x4C": {
        "abbreviation": "BR-SAT-MON",
        "protocol": "Backroom SATNET Monitoring",
        "references": "n/a"
    },
    "0x4D": {
        "abbreviation": "SUN-ND",
        "protocol": "SUN ND PROTOCOL-Temporary",
        "references": "n/a"
    },
    "0x4E": {
        "abbreviation": "WB-MON",
        "protocol": "WIDEBAND Monitoring",
        "references": "n/a"
    },
    "0x4F": {
        "abbreviation": "WB-EXPAK",
        "protocol": "WIDEBAND EXPAK",
        "references": "n/a"
    },
    "0x50": {
        "abbreviation": "ISO-IP",
        "protocol": "International Organization for Standardization Internet PRotocol",
        "references": "n/a"
    },
    "0x51": {
        "abbreviation": "VMTP",
        "protocol": "Versatile Message Transaction Protocol",
        "references": "RFC 1045"
    },
    "0x52": {
        "abbreviation": "SECURE-VMTP",
        "protocol": "Secure Versatile Message Transaction Protocol",
        "references": "RFC 1045"
    },
    "0x53": {
        "abbreviation": "",
        "protocol": "",
        "references": ""
    },
    "0x54": {
        "abbreviation": "VINES",
        "protocol": "VINES",
        "references": "n/a"
    },
    "0x55": {
        "abbreviation": "TTP",
        "protocol": "Transaction Transport Protocol",
        "references": "n/a"
    },
    "0x56": {
        "abbreviation": "IPTM",
        "protocol": "Internet Protocol Traffic Manager",
        "references": "n/a"
    },
    "0x57": {
        "abbreviation": "TCF",
        "protocol": "TCF",
        "references": "n/a"
    },
    "0x58": {
        "abbreviation": "EIGRP",
        "protocol": "Enhanced Interior Gateway Routing Protocol",
        "references": "RFC7868"
    },
    "0x59": {
        "abbreviation": "OSPF",
        "protocol": "Open Shortest Path First",
        "references": "RFC 2328"
    },
    "0x5A": {
        "abbreviation": "Sprite-RPC",
        "protocol": "Sprite RPC Protocol",
        "references": "n/a"
    },
    "0x5B": {
        "abbreviation": "LARP",
        "protocol": "Locus Address resolution Protocol",
        "references": "n/a"
    },
    "0x5C": {
        "abbreviation": "MTP",
        "protocol": "Multicast Transprot Protocol",
        "references": "n/a"
    },
    "0x5D": {
        "abbreviation": "AX.25",
        "protocol": "AX.25",
        "references": "n/a"
    },
    "0x5E": {
        "abbreviation": "OS",
        "protocol": "KAQ9 NOS Compatible IP over IP Tunneling",
        "references": "n/a"
    },
    "0x5F": {
        "abbreviation": "MICP",
        "protocol": "Mobile Internetworking Control Protocol",
        "references": "n/a"
    },
    "0x60": {
        "abbreviation": "SCC-SP",
        "protocol": "Semaphore Communications Security Protocol",
        "references": "n/a"
    },
    "0x61": {
        "abbreviation": "ETHERIP",
        "protocol": "Ethernet-within-IP Encapsulation",
        "references": "RFC 3378"
    },
    "0x62": {
        "abbreviation": "ENCAP",
        "protocol": "Encapsulation Header",
        "references": "RFC 1241"
    },
    "0x63": {
        "abbreviation": "n/a",
        "protocol": "Any Private Encryption Scheme",
        "references": "n/a"
    },
    "0x64": {
        "abbreviation": "GMTP",
        "protocol": "GMTP",
        "references": "n/a"
    },
    "0x65": {
        "abbreviation": "IFMP",
        "protocol": "Ipsilon Flow Management Protocol",
        "references": "n/a"
    },
    "0x66": {
        "abbreviation": "PNNI",
        "protocol": "Private Network-to-Network over IP",
        "references": "n/a"
    },
    "0x67": {
        "abbreviation": "PIM",
        "protocol": "Protocol Independent Multicast",
        "references": "n/a"
    },
    "0x68": {
        "abbreviation": "ARIS",
        "protocol": "Aggregate Route IP Switching Protocol",
        "references": "n/a"
    },
    "0x69": {
        "abbreviation": "SCPS",
        "protocol": "Space Communications Protocol Standards",
        "references": "SCPS-TP"
    },
    "0x6A": {
        "abbreviation": "QNX",
        "protocol": "QNX",
        "references": "n/a"
    },
    "0x6B": {
        "abbreviation": "A/N",
        "protocol": "Active Networks",
        "references": "n/a"
    },
    "0x6C": {
        "abbreviation": "IPComp",
        "protocol": "IP Payload Compression Protocol",
        "references": "RFC 3173"
    },
    "0x6D": {
        "abbreviation": "SNP",
        "protocol": "Sitara Networks Protocol",
        "references": "n/a"
    },
    "0x6E": {
        "abbreviation": "Compaq-Peer",
        "protocol": "Compaq Peer Protocol",
        "references": "n/a"
    },
    "0x6F": {
        "abbreviation": "IXP-in-IP",
        "protocol": "IXP in IP",
        "references": "n/a"
    },
    "0x70": {
        "abbreviation": "VRRP",
        "protocol": "Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned)",
        "references": "RFC 5798"
    },
    "0x71": {
        "abbreviation": "PGM",
        "protocol": "Paramatic General Multicast Reliable Transport Protocol",
        "references": "RFC 3208"
    },
    "0x72": {
        "abbreviation": "n/a",
        "protocol": "Any 0-hop Protocol",
        "references": "n/a"
    },
    "0x73": {
        "abbreviation": "L2TP",
        "protocol": "Layer 2 Tunneling Protocol Version 3",
        "references": "RFC 3931"
    },
    "0x74": {
        "abbreviation": "DDX",
        "protocol": "D-II Data Exchange",
        "references": "n/a"
    },
    "0x75": {
        "abbreviation": "IATP",
        "protocol": "Interactive Agent Transfer Protocol",
        "references": "n/a"
    },
    "0x76": {
        "abbreviation": "STP",
        "protocol": "Schedule Transfer Protocol",
        "references": "n/a"
    },
    "0x77": {
        "abbreviation": "SRP",
        "protocol": "SpectraLink Radio Protocol",
        "references": "n/a"
    },
    "0x78": {
        "abbreviation": "UTI",
        "protocol": "Universal Transport Interface Protocol",
        "references": "n/a"
    },
    "0x79": {
        "abbreviation": "SMP",
        "protocol": "Simple Message Protocol",
        "references": "n/a"
    },
    "0x7A": {
        "abbreviation": "SM",
        "protocol": "Simple Multicast Protocol",
        "references": "draft-perlman-simple-multicast-03"
    },
    "0x7B": {
        "abbreviation": "PTP",
        "protocol": "Performance Transparency Protocol",
        "references": "n/a"
    },
    "0x7C": {
        "abbreviation": "Is-IS over IP",
        "protocol": "Intermediate System to Intermediate System Protocol over IPv4",
        "references": "RFC 1142, RFC 1195"
    },
    "0x7D": {
        "abbreviation": "FIRE",
        "protocol": "Flexible Intra-AS Routing Environment",
        "references": "n/a"
    },
    "0x7E": {
        "abbreviation": "CRTP",
        "protocol": "Combat Radio Transport Protocol",
        "references": "n/a"
    },
    "0x7F": {
        "abbreviation": "CRUDP",
        "protocol": "Combat Radio User Datagram",
        "references": "n/a"
    },
    "0x80": {
        "abbreviation": "SSCOPMCE",
        "protocol": "Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment ",
        "references": "ITU Q.2111 (1999)"
    },
    "0x81": {
        "abbreviation": "IPLT",
        "protocol": "n/a",
        "references": "n/a"
    },
    "0x82": {
        "abbreviation": "SPS",
        "protocol": "Secure Packet Shield",
        "references": "n/a"
    },
    "0x83": {
        "abbreviation": "PIPE",
        "protocol": "Private IP Encapsulation within IP",
        "references": "Expired I-D draft-petri-mobileip=pipe-00"
    },
    "0x84": {
        "abbreviation": "SCTP",
        "protocol": "Stream Control Transmission Protocol",
        "references": "RFC 4960"
    },
    "0x85": {
        "abbreviation": "FC",
        "protocol": "Fibre Channel",
        "references": "n/a"
    },
    "0x86": {
        "abbreviation": "RSVP-E2E-IGNORE",
        "protocol": "Reservation Protocol End-to-End Ignore",
        "references": "RFC 3175"
    },
    "0x87": {
        "abbreviation": "Mobility Header",
        "protocol": "Mobility Extension Header for IPv6",
        "references": "RFC 6275"
    },
    "0x88": {
        "abbreviation": "UDPLite",
        "protocol": "Lightweight User Datagram Protocol",
        "references": "RFC 3828"
    },
    "0x89": {
        "abbreviation": "MPLS-in-IP",
        "protocol": "Multiprotocol Label Switching Encapsulated in IP",
        "references": "RFC 4023, RFC 5332"
    },
    "0x8A": {
        "abbreviation": "manet",
        "protocol": "Mobile AD HOC Network Protocols",
        "references": "RFC 5498"
    },
    "0x8B": {
        "abbreviation": "HIP",
        "protocol": "Host Identity Protocol",
        "references": "RFC 5201"
    },
    "0x8C": {
        "abbreviation": "Shim6",
        "protocol": "Site Multihoming by IPv6 Intermediation",
        "references": "RFC 5533"
    },
    "0x8D": {
        "abbreviation": "WESP",
        "protocol": " Wrapped Encapsulating Security Payload",
        "references": "RFC 5840"
    },
    "0x8E": {
        "abbreviation": "ROHC",
        "protocol": "Robust Header Compression",
        "references": "RFC 5856"
    },
    "0x8F": {
        "abbreviation": "Ethernet",
        "protocol": "Segment Routing over IPv6",
        "references": "RFC 8986"
    },
    "0x90": {
        "abbreviation": "AGGFRAG",
        "protocol": "AGGFRAG Encapsulation Payload for ESP",
        "references": "RFC 9347"
    },
    "0x91": {
        "abbreviation": "NSH",
        "protocol": "Network Service Header",
        "references": "draft-ietf-spring-nsh-sr"
    }
}

ip_vers_dict= {
    0: {
        "description": "Internet Protocol, pre IPv4",
        "status": "Reserved"
    },
    1: {
        "description": "n/a",
        "status": "Unassigned"
    },
    2: {
        "description": "n/a",
        "status": "Unassigned"
    },
    3: {
        "description": "n/a",
        "status": "Unassigned"
    },
    4: {
        "description": "Internet Protocol Version 4 (IPv4)",
        "status": "Active"
    },
    5: {
        "description": "Internet Stream Protocol (ST or ST II)",
        "status": "Obsolete"
    },
    6: {
        "description": "Internet Protocol Version 6 (IPv6)",
        "status": "Active"
    },
    7: {
        "description": "TP/IX THe Next Internet (IPv7)",
        "status": "Obsolete"
    },
    8: {
        "description": "P Internet Protocol (PIP)",
        "status": "Obsolete"
    },
    9: {
        "description": "IPv9 or Chinese IPv9",
        "status": "Obsolete"
    },
    10: {
        "description": "n/a",
        "status": "Unassigned"
    },
    11: {
        "description": "n/a",
        "status": "Unassigned"
    },
    12: {
        "description": "n/a",
        "status": "Unassigned"
    },
    13: {
        "description": "n/a",
        "status": "Unassigned"
    },
    14: {
        "description": "n/a",
        "status": "Unassigned"
    },
    15: {
        "description": "Version field sentinel value",
        "status": "Reserved"
    }
}



# convert the hex of EtherType to the string name
def get_eth_str(protocol):
    if protocol in eth_dict.keys():
        return eth_dict.get(protocol)
    else:
        return 'error: protocol not found....'


# get the IP protocol data from the hex value
def get_ip_protocol(protocol):
    if protocol in ip_prot_dict.keys():
        return ip_prot_dict.get(protocol).get("abbreviation"), ip_prot_dict.get(protocol).get("protocol"), ip_prot_dict.get(protocol).get("references"), 0
    elif protocol in ['0x' + '{:02x}'.format(x).upper() for x in range(146, 253)]:
        return 'n/a', 'Unassigned', 'n/a', 1
    elif protocol in ['0x' + '{:02x}'.format(x).upper() for x in range(253, 255)]:
        return 'n/a', 'Experimenting and Testing', 'RFC 3692', 2
    elif protocol == '0xFF':
        return 'n/a', 'Reserved', 'n/a', 3
    else:
        return None, None, None, 4


# get the version of the IP packet
def get_ip_vers(version):
    if version in ip_vers_dict:
        return ip_vers_dict.get(version).get("description"), ip_vers_dict.get(version).get('status'), 0
    else:
        return None, None, 1