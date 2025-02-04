# Python Packet Sniffer (Name pending)

This is a python-based network packet sniffer and capture software. This project was developed for a software engineering class 'Advanced Topics in Programming', where we are tasked with creating a project using technologies/libraries we have not used before. I chose to create software that unpacks network traffic, like WireShark. This software also uses other libraries I have not used before, such as TKinter, libpcap, and py2exe. More libraries may be added as the project is continued. More information about the proposal of the project can be found in [PROPOSAL.md](https://github.com/Zack-Fleming/python_packet_sniffer/blob/master/PROPOSAL.md).


## Features

The features of this project can be split into four categories:
 1. Packet sniffing - features regarding the packet sniffing and packet data unpacking
 2. Packet capturing - features regarding the saving and opening of captured packet data (.pcap files)
 3. GUI - features regarding the GUI components
 4. Creature Comforts - features regarding components that are nice to have but are not vital to the project


### Packet Sniffing Features

Mainly unpacking the ethernet frame and various IP Packets including IPv4, IPv6, UDP, TCP/IP, etc. Each packet has a varying format and will require a different algorithm to properly unpack the data. The unpacked data will be turned into text, where the label of the text is followed by the text. In the case of integers, the decimal (DEC), hexadecimal (HEX), and binary (BIN) representations will be printed. An example is as follows:

> Source IP: 127.0.0.1
>
> Version: \
> &emsp;&emsp;(DEC): 4 \
> &emsp;&emsp;(BIN): 0b0100 \
> &emsp;&emsp;(HEX): 0x04


### Packet Capturing Features

The main features of the capturing of packets are controls regarding the creation and manipulation of .pcap files. This is mainly done through the libpcap library in python. I will note that this library can also list and select interfaces and capture the packets. I am currently not using these features, yet. I may in the future move these features to this library, if using sockets does not provide the features I want.

The aforementioned capturing controls are:
 - **START** - Starts the packet capturing. Is disabled when using an opened .pcap file
 - **STOP** - Stops the capturing of packet data. Is disabled when using an opened .pcap file
 - **NEW** - creates a new capture session. If one is already open/active then the normal 'Do you want to save changes?' dialog will show
 - **OPEN** - opens a previously saved pcap file
 - **SAVE** - saves the current capture session
 - **EDIT** - gives the opportunity to selectively remove packets of the capture
 - **QUIT** - exits the program
 - **FILTERING** - allows the filtering of captured packet data. This is a non-destructive filter where the data is only not shown. Examples of possible filter are:
    - Source MAC/IP/port
    - Destination MAC/IP/port
    - Protocol (i.e. UDP, TCP, ICMp, etc.)
    - Flags (fragmentation, no fragmentation, etc.)
    - Type of Service
    - ect.


### GUI Features

The GUI of the software will contain a few main components. The components include, menu/search bar, packet list view, hex data view, text data view, and settings window. The GUI will be made using TKinter, as mentioned before, and will use the grid layout system. This system allows the elements of the GUI to resize dynamically with the window and removes hard coded position and size values. GUI components will now have written out in more detail.

#### Menu/Search Bar

The menu and search bar contains program controls as well as the filter search bar and accompanying active filter(s) list. The menu section of this bar is split into two dropdowns, file and capture operations. The file operations contain: NEW, OPEN, and SAVE options. The capture operations dropdown contain: START, STOP, and EDIT options. 


### Creature Comfort Features

WIP
