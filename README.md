# Python Packet Sniffer (Name pending)

This is a python-based network packet sniffer and capture software. This project was developed for a software engineering class 'Advanced Topics in Programming', where we are tasked with creating a project using technologies/libraries we have not used before. I chose to create software that unpacks network traffic, like WireShark. This software also uses other libraries I have not used before, such as TKinter, libpcap, and py2exe. More libraries may be added as the project is continued. More information about the proposal of the project can be found in [PROPOSAL.md](https://github.com/Zack-Fleming/python_packet_sniffer/blob/master/PROPOSAL.md).


## Security Disclaimer

This software has the ability to expose personal information or information not for your eyes. The developer of this software does not take responsibility for any reprocussions from revealing secret or personally identifiable infomration. This software was made for a class, and is for testing purposes and learning purposes only. Use this software at your own risk. 


## Libraries Used

During the process of development, some of the libraries were changed and new ones were added. The following libraries were used:
 1. tkinter - Python GUI library. [tkinter Docs](https://docs.python.org/3/library/tkinter.html).
 2. CustomTkinter - modernized Python GUI library, built on tkinter. [CustomTkinter](https://customtkinter.tomschimansky.com/).
 3. CTkXYFrame - CTkScrollFrame with horizontal and vertical scrollbars. [CTkXYFrame Docs](https://github.com/Akascape/CTkXYFrame).
 4. tkinter-tooltip - tkinter tooltip widget, displays messages on hover. [tkinter-tooltip Docs](https://gnikit.github.io/tkinter-tooltip/).
 5. python-libpcap - python pcap file and network sniffer library. [python-libpcap Docs](https://python-libpcap.readthedocs.io/en/latest/).


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

#### Packet List

The packet list pane, by default, takes up around half the height of the window, and contains the list of captured packets of the current capture or the list of filtered packets. The list is in a table-like format, with the following columns: ID, Timestamp, Packet Length, Source IP/MAC, Destination IP/Mac, Protocol, Info. Each protocol will have its own background color or easy differentiation. These colors will be customizable when the theme customization is implemented. The user will be able to set multiple protocols to the same color, if they whish to group certain protocol(s) in the same 'group'. Users may also select the columns shown in the packet list pane, if they do not wish to see certain columns.

#### HEX/BIN Viewer

The hexadecimal or binary viewer pane has three main sections: address, HEX/BIN data, and ASCII data. The address shows the index/address of the data in the packet. The HEX/BIN data section  show the data of the packet in either HEX or BIN. The ASCII data section, shows the data in the packet using the ASCII representation, with non-printable characters as a ghostly dot, showing the number of characters. If the pane is in HEX mode, each line has 16 bytes of data, just like any other hex viewer/editor. However, when in BIN mode, the data is in four bytes per line, with a column space in between each byte. 

The various header keys will be color coded in the HEX/BIN viewer and in the text viewer. This color coding will be the background of the HEX/BIN viewer and the font color, foreground color, of the text pane. These colors are also user customizable, just like any other color in the program. Such color customization will be documented in the 'Theme Specification' section of the README.

#### Text Viewer

The text viewer pane will show the data of the packets in a key-value format, as shown under [Packet Sniffing Features](#packet-sniffing-features). For the various encapsulations will be under an accompanying drop-down. For example, the Ethernet frame will have a drop down section just like each type of packet, An example of this is shown below:

> Ethernet Frame: v <-- dropdown \
> &emsp;&emsp;< EHTERNET FRAME DATA > \
> &emsp;&emsp;IPv4 Packet: v <-- dropdown \
> &emsp;&emsp;&emsp;&emsp;< IPv4 PACKET DATA > \
> &emsp;&emsp;&emsp;&emsp;TCP/IP Packet: v <-- dropdown \
> &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;< TCP/IP PACKET DATA >

OR 

> Ethernet Frame: v <-- dropdown \
> &emsp;&emsp;< EHTERNET FRAME DATA > \
> IPv4 Packet: v <-- dropdown \
> &emsp;&emsp;< IPv4 PACKET DATA > \
> TCP/IP Packet: v <-- dropdown \
> &emsp;&emsp;< TCP/IP PACKET DATA >

The first example would show the layered encapsulation of the payload of the traffic. As in the example, it would show that a TCP/IP packet is inside an IPv4 Packet, which is inside an Ethernet Frame. The second example would just show each encapsulated packet as their own section, but would not necessarily show the layers of encapsulation. 


### Creature Comfort Features

The bulk of the creature comforts is the ability to customize the theme colors of the program. This is split up into adding the theme customization settings window, use of a custom theme file format, and importing and exporting themes. The other portion of creature comforts is code to make the software platform independent. 

#### Theme Customization

The theme customization will allow the user to change the colors for each widget of the window. For example, buttons have a background, foreground, active background, and active foreground color to change. Font family and sizes will also be options for either the program as a whole or for each widget. 

Color customizations can be done by either writing the color HEX codes directly into the provided textbox, or by using a color picker. The color picker will automatically put the Hex code of the selected color. 

#### Custom Theme File Format

The custom theme file specification will use packed bytes to shrink the stored data. This is just like how some bytes in the various network packets will hole multiple different fields. For example, the first byte in the IPv4 packet holds the version and Internet Header Length. Each field is only four bits and together take up one byte. The theme specification will use a similar tactic. For example, the maximum used font size is 72. 72 in binary only takes up 7 of eight bits. The last unused bit could be the start of the next field.

The Specification will also be used in the import/export of themes. When the full specification is laid out, a graphic will be added below. Currentl0\y, the project is still in a nearly stage, mainly consisting of the network packet sniffing tests and GUi tests. The theme specification will be laid out during the creation of the GUi or when most of the envisioned features have been added. 

#### Platform Independence

Currently, the project uses the AF_PACKET option under the socket library to capture packets. This option is not available in the Windows Operating System. For the project to run on Windows, another packet capturing library must be used, or different options in the socket library. 

Due to the non direct method of binding the created socket to a specified interface for capturing, the capturing of packets may be moved to libpcap instead. Libpcap can list interfaces and has a direct method for binding to an interface, and can list the interfaces to choose from as well. Even though the packets will be captured with the new library, the actual unpacking for printing will still be done manually with struct and bit operations.


## Things Learned Along The Way

This section is dedicated to the things I have learned while developing this project. This includes the successes and failures. As Bram Stoker said, "We learn from failiure, not from success!". Examples of this quote can be seen with every invention ever made. For example, the light bulb and the 10,000 failed filiments, or the failed test flights of the Wright brothers. Failiure can give insight to what does not work and what may work at the same time. 

### 1. Bit Ordering Qurkyness

Struct uses a specified bit ordering in order to know how to reassemble the extracted bytes. Most CPUs like Intel, AMD, and ARM run in little-endian mode, where the least significant byte is stored in the lowest address of an integer. The use of struct uses the '!' option, which according to their documentation is network, or bid-endian, mode. For some ofthe development of this project, I used a linux VM. This showed some quirky behavior, as HEX values were backwards from what they are expected to be.

For some reason, the VM was using the opposite byte order than the host machine, even when using the same network mode for struct. I noticed this when adding the ethertype JSON array, that contains a list of the ethertype HEX values and their corresponding description. I printed out the captured ethertypes and I was getting '0x0008', '0xDD86', and '0x0608'. These values are not in the table of ethertype values, however 0x86DD and 0x0806 are. I then realized the byt ordering was backwards and had to change it only for the VM. This fixed the issue, however, I still don't know why I had to reverse the byte ordering on the VM only. The byte odering is decided by the CPU not the OS.

### 2. Images

All images/icons are from Font Awesome.

#### a. Random Icons

The favicon images for the title bar of the progam uses the .ico format, as usual. The images were downloaded as an SVG from Font Awesome, and converted to .ico, as the `.iconphoto()` method only allows an .ico image.

During the application initalizing step, the ico file is picked from a random icon, using a list of file paths. The list of file paths can allow adding/removing icons quickly.

#### b. Using SVGs

This project uses SVG images for all the icons, except for the favicon in the title bar. By default, the image tag for Tkinter and CTk do not allow the use of an SVG, and throws all sorts of errors, when reading the files. To fix this, I found the tksvg package, which does the proper conversions for the Tkinter and CTk images. 

#### c. Editing SVGs

For the theme specification, still planned in the future, the ability to edit the colors of the various SVGs used as icons in the applicaiton. The editing is done using the following steps:
 1. SVG is loaded into a its element tree
 2. Fill attribute is searched for
 3. Input color is writen to the fill attribute
 4. New data is written to the file

I used the `xml.etree` package that is inside the base install of Python.

### 3. Multithreading Shenanigans

#### a. How to Kill a Tread

By default, the `threading.Thread` does not have a pethod to kill the thread at any time. Instead one must either wait for the tread to do its job, or use an event to kill the thread. THere is an additional package called PyThreadKiller, that does contain a `.kill()` method, that can immediately kill a thread. I still used used an event to determin when the while loop should end; alingside the `.join()` method to allow the thread to process for a determined time, before killing it will `.kill()`.

#### b. Table Stuff

Due to the way I have implemented multithreading, the table sometimes containes rows that only have a few of the cells added, before the thread was killed. Unless I missed something, I could not fic this issue, no matter what I tried. If I will develop this project after the end of the class its for, I will revisit the method used to add the dat to the custom table class or the multithreading implementation.

#### c. CTkLabel Giving Problems

I was forced to use the label in the base tkinter, due to the CtkLabel giving errors, when used in the table. I think this is due to the label beinh half initialized before the thread initializing the label is terminated. The error is: `attributeerror: 'ctklabel' object has no attribute '_font'. did you mean: '_root'?`. This is another thing to revisit, if I would continue this project.
