# Python Packet Sniffer (WireShark-like project)


## Introduction

This project is for Advanced Topics in Programming, as part of the Software Development and Information Management major. 

This project aims to provide a tool to explore layers 2, 3, and 4 of the OSI model. Specifically, this project will let users understand the formatting of Ethernet Frames and IP Packets. The project will be split into two portions: the packet sniffing and data analysis and visualization of the packet data. This project can also be coupled with a flagging configuration, where packets containing the filter conditions. 

Requirements of the project:
 1. Capture incoming network traffic for analysis
 2. Unpack packet data 
 3. Print out data in various formats (BIN | HEX | OCTAL | ETC.)
 4. Visualize data in readable format w\ labels and color formatting
 5. Show list of captured packets in color-formatted list
 6. Filter shown packets based on criteria (SRC | DEST | PORT | PROTOCOL | ETC.)
     - The packets not shown with a filter are not deleted, they are just not shown
 7. Have controls for recording data (START | STOP | NEW | SAVE | OPEN | EDIT)
 8. Save captured data in file format
     - If possible, use the .pcap format
     - If not, use custom file format
 9. Allow for the tagging of packets as (SAFE | SUSPECT | UNSAFE )
     - Least priority
     - careful algorithm to lessen false positives
 10. Allow for color customization
     - Also least priority
     - light/dark theme
     - settings for the color highlighting for data
 11. Highlight data fields that is hovered
     - If data in the HEX view is hovered/selected, highlight the data in the print view


## Technology

This project will use a variety of technologies and libraries including:
 - Python
 - Socket/scapy
 - TKinter
 - Raspberry PI
 - Struct
 - python-libcap
 - py2exe & py2app

The project will be using a Raspberry PI due to its portable nature and highly customizable GPIO [1]. The raspberry PI is a very customizable computer that does not have the bloat of other Operating Systems and gives access to the raw GPIO of the computer, both on the header and standardized ports (i.e. USB, RJ45, etc.). The form factor ofthe Raspberry PI makes it a great platform for embedded applications or applications that need to be smaller. The use of the software of this project does not need to use a Raspberry PI, as the use of project uses Python which is platform independent. The use of a Raspberry PI is to learn the use of a new platform.

Python is used for both its simplicity and its use in data science and analysis. Python is also partially platform independent. The libraries used may change due to platform dependence. For example, in a linux OS this project will use socket.AF_PACKET parameter for the network socket used. This is a field that is not available in Windows platforms and will have to use another library instead. 

Socket is the main Python library used for this project. Socket gives low-level acces to network adapters [2]. The library also gives direct system call access to the sockets on network adapters. This specific feature will not be used, instead reading the raw packet and frame data of the adapter will be used. Socket can even allow the ability to specify the adapter used. However, the use of this option requires root access in order to set the option. 

This project will also be using Scapy for network traffic operations. Scapy is a network packet manipulation library for Python [8]. Scapy can also decode packets as well. This funcionality will only be used to compare results of decoding to this project, as that is the main purpose of this project. Using a library to accomplish this, would circumvent exploring the protocols on a low-level. Scapy is also used to create packets for network programming. I will use this functionality to generate traffic with specific options and dat set, in order to test the decoding of packets and flagging of certain data. 

For the GUI and visualization, this project will be using TKinter [5]. TKinter is a simple GUI library for Python that is decently documented, allowing for easy use. There are other libraries such as PyQt, Kivy, wxPython. TKinter is the simplest of the GUI libraries. If the GUI side of the project is to complex, another library may be supplemented.

Struct is used to unpack the data using predictable formats and sizes [6]. Struct can also pack data into a format for the pcap file generation or custom file generation. The formatting options of input data are used for headers where the data is in predicable formats and lengths that do not change. For example, the IPv6 packet header is a static size and the location and size of the options are also static. For IPv4, custom data handling is required due to some bytes of data holding multiple fields of different sizes.

Python-libcap is a library that provides functionality of pcap files to python [7]. The pcap file is mainly used in programs like WireShark and Ncap. The file contains the raw packet data and timestamp for the duration of the capture. These files can be one or two packets, or thousands of packets. python-libcap can also be used to do the traffic capturing and list network interfaces. I will not be using the capturing feature, as my program will be implementing that feature from scratch.

Py2exe and py2app are extensions that can create executables for windows and Mac OS respectively [3] [4]. They both have the ability to bundle dependencies inside the executable or require them to be placed into the same directory or a defined directory. Py2app has the downside of requiring the building process to be on a mac device. I may need to create a Mac OS VM to copy the source code to and build and test the executable. I would assume that the py2exe would also require the executable be built on a windows machine, however, the documentation of the library does not specify this face. If it does, I already have two windows machines, and would have to copy the source to one of them, similarly to the Mac OS VM.


## Platform

The main platform for this project will be Linux, the same platform it will be developed with. A portion of this project will be used to try and 'port' the software to other platforms, or use code to detect the OS platform and change the function calls accordingly. For example, socket.AF_PACKET is Linux only and not available on MAc OS or Windows. For those platforms, I would have to change the function used to capture the packet. I would probably use either Scapy or Python-libcap to do this. Also, the GUI of the program is platform independent using TKinter. If another GUI library Kivy or wxPython could add features such as platform inherited look and feel, instead of using the default look and feel of TKinter on all platforms. Other than the GUI and back-end capturing of packets, the user should not notice anything different between platforms. File operations may be a bit different, due to the varying security of the different platforms. However, the OS package of python should take care of it. Also, on Linux, the program must be run using sudo or root, due to the low-level use of the system hardware. I suspect the program must be run as administrator in windows or given permissions in Mac OS. Finally, the program will be compiled into an executable or runnable file that does not need a command to be run in terminal. As mentioned previously, I will be using py2exe for this task.


## Project Plan

Below is the Gantt chart for the project. the chart is broken into four sprints:
 - Sprint 1 Core Functionality - The main fuctionality of unpacking network traffiuc is added
     - functionality for the unpacking of ethernet frames and the different types of IP packets
 - Sprint 2 GUI Components - The GUI of the program is added
     - The main GUI, main menus, HEX data view, and text data view
 - Sprint 3 Capture Controls - Controls for captures is added
     - Controls include (NEW | OPEN | SAVE | START | STOP | EDIT | QUIT)
 - Sprint 4 Creature Comforts - nice features are added
     - features like the ability to customize themes and import/export themes

![Gantt chart for the project](https://github.com/Zack-Fleming/python_sniffer_and_Firewall/blob/master/gantt-chart.png)


## Works Cited

[1] - Raspberry PI 5 Technical Specifications, https://www.raspberrypi.com/products/raspberry-pi-5/ \
[2] - Socket Library Documentation, https://docs.python.org/3/library/socket.html \
[3] - Py2exe Library Documentation, https://www.py2exe.org \
[4] - Py2app Library Documentation, https://py2app.readthedocs.io/en/latest/ \
[5] - TKinter Library Documentation, https://docs.python.org/3/library/tkinter.html \
[6] - Struct Library Documentation, https://docs.python.org/3/library/struct.html \
[7] - python-libpcap Library Documentation, https://github.com/caizhengxin/python-libpcap \
[8] - Scapy Library Documentation, https://scapy.net \
