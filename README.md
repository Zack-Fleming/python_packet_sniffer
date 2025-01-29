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

The project will be using a Raspberry PI due to its portable nature and highly customizable GPIO. The raspberry PI is a very customizable computer that does not have the bloat of other Operating Systems and gives access to the raw GPIO of the computer, both on the header and standardized ports (i.e. USB, RJ45, etc.).

Python is used for both its simplicity and its use in data science and analysis. Python is also partially platform independent. The libraries used may change due to platform. For example, in a linux OS this project will use socket.AF_PACKET for the parameter for the network socket used. THis is a field that is not known in Windows platforms and will have to use another library called scapy. 

Socket and or Scapy will be used for this project for the capturing of hte network traffic data. Socket is used for the Linux-based OS like the Raspberry PI OS. Scapy would be the substitute for windows platforms. The library use could be simplified to only Scapy for OS independence. However, the sniffer code uses the socket library and would have to be reworked for scapy. Also, socket comes with the base install of Python and Scapy does not. This would simplify the installation of the software for another user. Also, scapy can be used to simulate specific types of traffic, for testing either the main capturing or flagging of the network traffic. 

For the GUI and visualization, this project will be using TKinter. TKinter is a simple GUI library for Python that is decently documented, allowing for easy use. THere are other libraries such as PyQt, Kivy, wxPython. TKinter is the simplest of the GUI libraries. If the GUI side of the project is to complex, another library may be supplemented.

Struct is used to unpack the data using predictable formats and sizes. Struct can also pack data into a format for the pcap file generation or custom file generation. The formatting options of input data are used for headers where the data is in predicable formats and lengths that do not change. For example, the IPv6 packet header is a static size and the location and size of the options are also static. For IPv4, custom data handling is required due to some bytes of data holding multiple fields of different sizes.

Python-libcap is a library that provides functionality of pcap files to python. The pcap file is mainly used in programs like WireShark and Ncap. The file contains the raw packet data and timestamp for the duration of the capture. These files can be one or two packets, or thousands of packets. python-libcap can also be used to do the traffic capturing and list network interfaces. I will not be using the capturing feature, as my program will be implementing that feature from scratch.

Py2exe and py2app are extensions that can create executables for windows and Mac Os respectively. They both have the ability to bundle dependencies inside the executable or require them to be placed into the same directory or a defined directory. Py2app has the downside of requiring the building process to be on a mac device. I may need to create a Mac OS VM to copy the source code to and build and test the executable. I would assume that the py2exe would also require the executable be built on a windows machine, however, the documentation of the library does not specify this face. If it does, I already have two windows machines, and would have to copy the source to one of them, similarly to the Mac OS VM.


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
