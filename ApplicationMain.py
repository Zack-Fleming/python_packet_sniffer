# import(s)
# main GUI libraries
import tkinter
import tkinter as tk
import customtkinter as ctk
from customtkinter import CTkToplevel, filedialog, CTkEntry, CTkLabel
from utility.CTkXYFrame import CTkXYFrame
# additional libraries for GUI
from tktooltip import ToolTip
# network sniffing
from pylibpcap import get_iface_list, rpcap
from pylibpcap.base import Sniff
# misc. libraries
from utility.photo_functions import *
from utility.sniffer import *
from utility.Table import *
from utility.sniffer_data_sets import get_ip_protocol, get_icmp_type, get_eth_str
from utility.chars import *
# system libraries
import os
from PyThreadKiller import PyThreadKiller
from pwd import getpwnam
import datetime
import pytz

# setting default/startup theme and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# Application class
class Application(ctk.CTk):
    # *************************************************************************
    # *                                 FLAGS                                 *
    # *************************************************************************
    # flag for if the captured data is saved
    # open the 'save before exiting' dialog window
    is_saved = False
    # flag for if currently sniffing packets
    is_sniffing = False
    # determine if localhost traffic is filtered from the table
    filter_local = True
    # *************************************************************************
    # *                                OBJECTS                                *
    # *************************************************************************
    # the sniffer object
    sniffer_obj = None
    # thread to do the sniffing
    sniff_thread = None
    # thread stop event
    stop_event = threading.Event()
    # *************************************************************************
    # *                           LISTS/ARRAYS/ETC.                           *
    # *************************************************************************
    # keep track of the pressed state of keys
    pressed_keys = {}
    # keeps track of the captures packets
    captured_packets = [] # use len() + 1 for table index
    # keep track of the column headers for packet table
    headers = ["#", "Timestamp", "Packet Len.", "Src. IP", "Dest. IP", "Src Port", "Dest Port", "Protocol", "Sel Packet"]
    # *************************************************************************
    # *                           REGULAR VARIABLES                           *
    # *************************************************************************
    # keeps track of the currently opened/saved file
    current_file = None
    # keep track of the current UI scale
    UI_scale = None
    # interface listening on
    interface = None


    def __init__(self):
        super().__init__() # call the init of the 'inherited class'

        self.after(1, self.show_interface_popup) # show a popup after the main windows is initialized

        # configure window settings
        self.title("Python Packet Sniffer")
        self.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}")
        self.iconphoto(True, make_app_icon())

        # add listener(s) for keybinds
        self.bind("<KeyPress>", self.on_key_press)
        self.bind("<KeyRelease>", self.on_key_release)

        # get the current UI scaling
        self.UI_scale = ctk.ScalingTracker.get_widget_scaling(self)

        # configuring the grid layout (3x1) (row x column)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure((1, 2), weight=1)

        # setup program font(s)
        # monospace for hex and binary view(s)
        mono_space = ("Fira Code", 21)

        # create the menu bar
        self.menu_bar = CTkFrame(self, height=40)
        self.menu_bar.grid(row=0, column=0, pady=0, sticky="new")

        # add the buttons to the menu bar
        # capture file operations
        self.new_capture = CTkButton(self.menu_bar, image=make_icon("images/icons/new_capture.svg", self.menu_bar._current_height-20), text="", corner_radius=0, width=30, command=self.new_cap)
        ToolTip(self.new_capture, msg="New Capture", delay=0.5)
        self.new_capture.pack(side=tk.LEFT, padx=5)
        self.open_capture = CTkButton(self.menu_bar, image=make_icon("images/icons/open_capture.svg", 20), text="", corner_radius=0, width=30, command=self.open_cap)
        ToolTip(self.open_capture, msg="Open Capture", delay=0.5)
        self.open_capture.pack(side=tk.LEFT)
        self.save_capture = CTkButton(self.menu_bar, image=make_icon("images/icons/save_capture.svg", 20), text="", corner_radius=0, width=30, command=lambda x=None, y=False: self.save_data(x, y))
        ToolTip(self.save_capture, msg="Save Capture", delay=0.5)
        self.save_capture.pack(side=tk.LEFT, padx=5)
        # data capture operations
        self.start_capture = CTkButton(self.menu_bar, image=make_icon("images/icons/start_capture.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.start_capture, msg="Start Capture", delay=0.5)
        self.start_capture.pack(side=tk.LEFT, padx=5)
        self.stop_capture = CTkButton(self.menu_bar, image=make_icon("images/icons/stop_capture.svg", 20), text="", corner_radius=0, width=30, command=self.stop_cap)
        ToolTip(self.stop_capture, msg="Stop Capture", delay=0.5)
        self.stop_capture.pack(side=tk.LEFT)
        self.edit_capture = CTkButton(self.menu_bar, image=make_icon("images/icons/edit_capture.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.edit_capture, msg="Edit Capture", delay=0.5)
        self.edit_capture.pack(side=tk.LEFT, padx=5)
        # misc operations
        self.quit = CTkButton(self.menu_bar, image=make_icon("images/icons/quit.svg", 20), text="", corner_radius=0, width=30, command=self.on_window_close)
        ToolTip(self.quit, msg="Quit", delay=0.5)
        self.quit.pack(side=tk.RIGHT, padx=5)
        self.about = CTkButton(self.menu_bar, image=make_icon("images/icons/info.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.about, msg="About", delay=0.5)
        self.about.pack(side=tk.RIGHT)
        self.settings = CTkButton(self.menu_bar, image=make_icon("images/icons/settings.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.settings, msg="Settings", delay=0.5)
        self.settings.pack(side=tk.RIGHT, padx=5)
        # filter search bar
        self.filter_frame = CTkFrame(self.menu_bar)
        self.filter_frame.pack(side=tk.LEFT, padx=5)
        self.filter_entry = CTkEntry(self.filter_frame, width=self._current_width/10, corner_radius=0)
        self.filter_entry.image = svg.SvgImage(file="images/icons/search.svg", scaletoheight=20)
        self.filter_entry.pack(side=tk.LEFT)
        self.filter_button = CTkButton(self.filter_frame, image=self.filter_entry.image, text="", width=30, corner_radius=0)
        self.filter_button.pack(side=tk.LEFT, fill="y")

        # packet list pane/table
        self.packet_scroll = CTkScrollableFrame(self)
        self.packet_scroll.grid(row=1, column=0, pady=0, sticky="nsew")
        self.packet_scroll.grid_columnconfigure(0, weight=1)
        # table of captured packets
        self.packet_table = Table(self.packet_scroll, 0, 0, "nsew", 0, 0, values=[self.headers])

        # data view pane
        self.data_view_pane = CTkFrame(self)
        self.data_view_pane.grid(row=2, column=0, pady=0, sticky="nsew")
        self.data_view_pane.grid_columnconfigure((0, 1), weight=1)
        self.data_view_pane.grid_rowconfigure(0, weight=1)
        # text data view
        self.text_pane = CTkXYFrame(self.data_view_pane)
        #self.text_pane = CTkScrollableFrame(self.data_view_pane, label_text="ASCII Packet Data")
        self.text_pane.grid(row=0, column=0, pady=0, sticky="nsew")
        #self.text_pane.pack(fill="both")
        self.ascii_pane_header = CTkLabel(self.text_pane, text="ASCII Packet Data", font=("Arial", 14))
        self.ascii_pane_header.grid(row=0, column=0, sticky="ew")
        self.ascii_text = CTkLabel(self.text_pane, text="", justify="left", font=("Arial", 14))
        self.ascii_text.grid(row=1, column=0, padx = 0, sticky="w")
        # hex/bin data view
        self.hex_bin_view = CTkScrollableFrame(self.data_view_pane, label_text="HEX/BIN Packet Data")
        self.hex_bin_view.grid(row=0, column=1, pady=0, sticky="nsew")
        #self.hex_bin_view.pack(fill="both")
        self.hex_bin_text = CTkLabel(self.hex_bin_view, text="Hexdump:", justify="left", font=("Courier", 14))
        self.hex_bin_text.grid(row=0, column=0, sticky="nsew")

    def show_interface_popup(self):
        """
        Shows the popup that has the user choose the interface being used for sniffing.

        Args:
            self: instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        popup = CTkToplevel()
        popup.title("Select Network Interface")
        popup.wm_attributes("-topmost", 1)

        popup_label = CTkLabel(popup, text="Select the network interface to listen on:")
        popup_label.pack()

        interfaces = get_iface_list()
        # print(interfaces) # debug purposes

        for interface in interfaces:
            button = CTkButton(popup, text=interface, command=lambda x=interface, y=popup: self.set_current_interface(x, y))
            button.pack(pady=5)

        popup.grab_set()
        popup.focus_set()
        popup.wait_window()

    def set_current_interface(self, name: str, popup: CTkToplevel):
        """
        Sets the interface for sniffing and starts the capture.

        Args:
            self: the instance of the Application class
            name: the name of the network interface to use
            popup: the popup, mainly for destroying it

        Returns:
            None

        Raises:
            None
        """
        # set interface name and set sniffing flag to True
        self.interface = name
        self.is_sniffing = True
        popup.destroy()
        # setup sniffing object using interface name
        self.sniffer_obj = Sniff(self.interface, count=-1, promisc=1, out_file="temp.pcap")
        # start second thread for sniffing of data
        self.sniff_thread = PyThreadKiller(target=self.sniff)
        self.sniff_thread.start()

    def sniff(self):
        """
        Main sniffing logic for application.

        Args:
            self: the instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        while not self.stop_event.is_set():
            for plen, t, buf in self.sniffer_obj.capture():
                self.captured_packets.append(dict(timestamp=t, packet_length=plen, data=buf)) # add packet to dictionary array

                # unpack the ethernet frame
                dest_mac, src_mac, eth_type, packet_data = unpack_frame(buf)

                # check if the source MAC and/or dest MAc are not all zeros
                # disregards all localhost traffic
                if (sum(src_mac) != 0 or sum(dest_mac) != 0) and self.filter_local:
                    # unpack an ARP packet
                    if eth_type == 2054:
                        hw_type, proto_type, hw_len, proto_len, op_code, send_hw, send_proto, target_hw, target_proto = unpack_arp(packet_data)
                        self.packet_table.add_row([str(len(self.captured_packets)), t, plen, format_ip(send_proto), format_ip(target_proto), "n/a", "n/a", get_eth_str('0x' + '{:04x}'.format(eth_type).upper()), None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))
                    # unpack IPv6 packet
                    elif eth_type == 34525:
                        version, traffic_class, flow_label, payload_length, next_header, hop_limit, ip6_src, ip6_dst, ipv6_payload = unpack_ipv6(packet_data)
                        self.packet_table.add_row([str(len(self.captured_packets)), t, plen, form_ipv6_addr(ip6_src), form_ipv6_addr(ip6_dst), "n/a", "n/a", get_eth_str('0x' + '{:04x}'.format(eth_type).upper()), None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))
                    # unpack IPv4 packet:
                    elif eth_type == 2048:
                        version, ihl, dscp, ecn, total_length, identification, flags, frag_off, ttl, protocol, head_check, ip4_src, ip4_dst, ipv4_payload = unpack_ipv4(packet_data)
                        proto_abbr, proto_name, proto_ref, code = get_ip_protocol('0x' + '{:02x}'.format(protocol).upper())

                        # unpack ICMP (0x01) - protocol
                        if protocol == 1:
                            type_code, subtype_code, icmp_checksum, icmp_data = unpack_icmp(ipv4_payload)
                            icmp_type, icmp_subtype, icmp_type_status, ret_code = get_icmp_type(str(type_code), str(subtype_code))
                            self.packet_table.add_row([str(len(self.captured_packets)), t, plen, format_ip(ip4_src), format_ip(ip4_dst), "n/a", "n/a", proto_name, None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))
                        # unpack TCP/IP packet (ox06) - protocol
                        elif protocol == 6:
                            src_port, dst_port, sequence_num, ack_num, data_offset, reserved, flags, window, tcp_checksum, upointer, tcp_data = unpack_tcp(ipv4_payload)
                            self.packet_table.add_row([str(len(self.captured_packets)), t, plen, format_ip(ip4_src), format_ip(ip4_dst), src_port, dst_port, proto_name, None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))
                        # unpack UDP packet (0x11) - protocol
                        elif protocol == 17:
                            src_port, dst_port, length, udp_checksum, udp_data = unpack_udp(ipv4_payload)
                            self.packet_table.add_row([str(len(self.captured_packets)), t, plen, format_ip(ip4_src), format_ip(ip4_dst), src_port, dst_port, proto_name, None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))

    def handle_table_button_click(self, index: int):
        """
        Intermediate method to handle the button click event for the table buttons.

        Args:
            self: the instance of the Application class
            index: index for grabbing the index in the captured_packets list.

        Returns:
            None

        Raises:
            None
        """
        self.set_ascii_pane(index)
        self.set_hex_pane(index, "HEX")

    def set_ascii_pane(self, index: int):
        """
        Sets the text of the ASCII text pane. Uses similar logic as the sniff function.

        Args:
            self: the instance of the Application class
            index: index to the captured_packets list

        Returns:
            None

        Raises:
            None

        """
        pack_dict = self.captured_packets[index - 1] # get the specified packet

        # info for the packet
        new_text = (f"Packet #{index} Data:" +
                    f"\n{t1}Length: {pack_dict.get("packet_length")} bytes" +
                    f"\n{t1}Timestamp (seconds): {pack_dict.get("timestamp")}" +
                    f"\n{t1}Timestamp (UTC): {datetime.datetime.fromtimestamp(pack_dict.get("timestamp"), pytz.UTC)}UTC"
        )

        #unpack the ethernet frame
        dest_mac, src_mac, eth_type, packet_data = unpack_frame(pack_dict.get("data"))

        # ethernet frame data
        new_text += ("\nEthernet Frame Data: "
                     f"\n{t1}Source MAC: {format_mac(src_mac)}\n{t1}Destination MAC: {format_mac(dest_mac)}"
                     f"\n{t1}Ether Type:"
                     f"\n{t2}(DEC): {eth_type}\n{t2}(BIN): {format(eth_type, '#018b')}"
                     f"\n{t2}(HEX): 0x{'{:04x}'.format(eth_type).upper()}\n{t2}(STR): {get_eth_str('0x' + '{:04x}'.format(eth_type).upper())}"
        )

        # unpack an ARP packet
        if eth_type == 2054:
            hw_type, proto_type, hw_len, proto_len, op_code, send_hw, send_proto, target_hw, target_proto = unpack_arp(packet_data)

            new_text += (f"\n{t1}Address Resolution Protocol Packet: "
                         f"\n{t2}Hardware Type: {hw_type}\n{t2}Protocol Type: {proto_type}"
                         f"\n{t2}Hardware Length: {hw_len}\n{t2}Protocol Length: {proto_len}"
                         f"\n{t2}Operation Code: {op_code} ({'request' if op_code == 1 else 'reply'})"
                         f"\n{t2}Sender Hardware Address: {format_mac(send_hw)}\n{t2}Sender Protocol Address: {format_ip(send_proto)}"
                         f"\n{t2}Target Hardware Address: {format_mac(target_hw)}\n{t2}Target Protocol Address: {format_ip(target_proto)}"
            )
        # unpack IPv6 packet
        elif eth_type == 34525:
            version, traffic_class, flow_label, payload_length, next_header, hop_limit, src, dst, ipv6_payload = unpack_ipv6(packet_data)

            new_text += (f"\n{t1}Internet Protocol Version 6 Packet:"
                         f"\n{t2}Version: {version}\n{t2}Traffic Class: {traffic_class}"
                         f"\n{t2}Flow Label: {flow_label}\n{t2}Payload Length: {payload_length}"
                         f"\n{t2}Next Header: {next_header}\n{t2}Hop Limit: {hop_limit}"
                         f"\n{t2}Source Address: {format_mac(src)}\n{t2}Destination Address: {format_mac(dst)}"
                         f"\n{t2}Payload Data: {ipv6_payload}"
            )
        # unpack IPv4 Packet
        elif eth_type == 2048:
            version, ihl, dscp, ecn, total_length, identification, flags, frag_off, ttl, protocol, head_check, src, dst, ipv4_payload = unpack_ipv4(packet_data)
            proto_abbr, proto_name, proto_ref, code = get_ip_protocol('0x' + '{:02x}'.format(protocol).upper())

            new_text += (f"\n{t1}Internet Protocol Version 4 Packet:"
                         f"\n{t2}Version: {version}\n{t2}Internet Header Length (IHL): {ihl}"
                         f"\n{t2}Differentiated Services Code Point (DSCP): {dscp}\n{t2}xplicit Congestion Notification (ESC): {ecn}"
                         f"\n{t2}Total Length: {total_length}\n{t2}Identification: {identification}"
                         f"\n{t2}Flags: {format(flags, '#05b')}\n{t3}Reserved bit (R): {(flags >> 2) & 1}\n{t3}Dont\'t Fragment bit (DF): {(flags >> 1) & 1}\n{t3}More Fragments bit (MF): {flags & 1}"
                         f"\n{t2}Fragment Offset: {frag_off}\n{t2}Time to Live (TTL): {ttl}"
                         f"\n{t2}Protocol: {protocol}\n{t3}Abbreviation: {proto_abbr}\n{t3}Full Name: {proto_name}\n{t3}References: {proto_ref}"
                         f"\n{t2}Header Checksum: {head_check}\n{t2}Source IP: {format_ip(src)}\n{t2}Destination IP: {format_ip(dst)}"
            )

            # protocol 1 (0x01) - ICMP
            if protocol == 1:
                type_code, subtype_code, checksum, icmp_data = unpack_icmp(ipv4_payload)
                icmp_type, icmp_subtype, icmp_type_status, ret_code = get_icmp_type(str(type_code), str(subtype_code))

                new_text += (f"\n{t2}Internet Control Message Protocol (ICMP): "
                             f"\n{t3}Type: {type_code} ({icmp_type}) ({icmp_type_status})"
                             f"\n{t3}Subtype: {subtype_code} ({icmp_subtype})"
                             F"\n{t3}Data: {icmp_data}"
                )
            # protocol 6 (0x06) - TCP/IP
            elif protocol == 6:
                src_port, dst_port, sequence_num, ack_num, data_offset, reserved, flags, window, checksum, upointer, tcp_data = unpack_tcp(ipv4_payload)

                new_text += (f"\n{t2}Transmission Control Protocol (TCP):"
                             f"\n{t3}Source Port: {src_port}\n{t3}Destination Port: {dst_port}"
                             f"\n{t3}Sequence Number: {sequence_num}\n{t3}Acknowledgement Number: {ack_num}"
                             f"\n{t3}Data Offset: {data_offset}\n{t3}Reserved Bits: {reserved}"
                             f"\n{t3}Flags: {flags}\n{t3}Sliding Window: {window}"
                             f"\n{t3}Checksum: {checksum}\n{t3}Urgent Pointer: {upointer}"
                             f"\n{t3}TCP Data: {tcp_data}"
                )
            # protocol 17 (0x0B) - UDP
            elif protocol == 17:
                src_port, dst_port, length, checksum, udp_data = unpack_udp(ipv4_payload)

                new_text += (f"\n{t2}User Datagram Protocol (UDP):"
                             f"\n{t3}Source Port: {src_port}\n{t3}Destination Port: {dst_port}"
                             f"\n{t3}Length: {length}\n{t3}Checksum: {checksum}"
                             f"\n{t3}UDP Data: {udp_data}"
                )


        # set the text of the label
        self.ascii_text.configure(text=new_text)

    def set_hex_pane(self, index: int, form: str):
        """
        Sets the text of the HEX/Bin pane

        Args:
             self: the instance of the Application class
             index: index for the captured_packets list
             form: format to show the data as ('HEX', 'BIN')
        """
        # make sure the inputted format is 'allowed'
        allowed_formats = {"BIN", "HEX"}
        if form not in allowed_formats:
            raise ValueError(f"Invalid format: {form}. Allowed formats: {allowed_formats}")

        # get the data from the packet dictionary
        data = self.captured_packets[index - 1].get("data")

        #strings to keep track of text
        new_text = f"{("0x%0.8X" % 0)}  "
        hex_line = ""
        ascii_line = ""

        # counter for 'address' and newline placement
        i = 0
        #iterate through the data list
        for byte in data:
            # convert the integer value to hex without '0x'
            hex_val = ("0x%0.2X" % byte).replace("0x", "")
            hex_line += hex_val
            ascii_line += (chr(byte) if chr(byte).isprintable() else ".")
            if i > 1: # account for the first two bytes (edge case)
                if (i + 1) % 16 != 0: # if the next byte is not dividable by 16, decide what to add in between bytes
                    if (i + 1) % 8 != 0: # if the next byte is dividable by 8, add a space
                        hex_line += " "
                    else: # add a couple of space, making the two columns of eight bytes
                        hex_line += "  "
                        ascii_line += "  "
                else: # if the next byte is dividable by 16, add the 'current' line of text and the newline
                    new_text += f"{hex_line}  {ascii_line}\n{("0x%0.8X" % (i + 1))}  "
                    hex_line = ""
                    ascii_line = ""
            else:
                hex_line += " "
            i += 1

        self.hex_bin_text.configure(text=new_text)
        #print(new_text) # debug purposes

    def on_key_press(self, event):
        """
        Sets the pressed key state to True, when pressed. Allows for multi key keybinds.

        Args:
            self: The instance of the Application class
            event: KeyPress event args

        Returns:
            None

        Raises:
            None
        """
        self.pressed_keys[event.keysym] = True
        # print(f'Key: {event.keysym}') # debugging purposes
        self.handle_key_press()

    def on_key_release(self, event):
        """
        Sets the pressed key state to False when released. Serves as a reset state for the key press state.

        Args:
            self: The instance of the Application class
            event: KeyPress event args

        Returns:
            None

        Raises:
            None
        """
        self.pressed_keys[event.keysym] = False
        self.handle_key_press()

    def handle_key_press(self):
        """
        Uses the key press dictionary to react to key presses.

        Args:
            self: The instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        # Ctrl + Q = quit
        if (self.pressed_keys.get("Control_L") or self.pressed_keys.get("Control_R")) and self.pressed_keys.get("q"):
            self.on_window_close()
        # Ctrl + Shift + + = Zoom in
        if self.pressed_keys.get("Control_L") and self.pressed_keys.get("Shift_L") and self.pressed_keys.get("plus"):
            self.zoom_in()
        # Ctrl + Shift + - = Zoom out
        if self.pressed_keys.get("Control_L") and self.pressed_keys.get("Shift_L") and self.pressed_keys.get("underscore"):
            self.zoom_out()
        # Ctrl + Shift + 0 = Reset zoom
        if self.pressed_keys.get("Control_L") and self.pressed_keys.get("Shift_L") and self.pressed_keys.get("parenright"):
            self.zoom_reset()
        if (self.pressed_keys.get("Control_L") or self.pressed_keys.get("Control_R")) and self.pressed_keys.get("o"):
            self.open_cap()
        if (self.pressed_keys.get("Control_L") or self.pressed_keys.get("Control_R")) and self.pressed_keys.get("s"):
            self.save_data()

    def zoom_in(self):
        """
        Zooms in the UI scaling by 20%.

        Args:
            self: The instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        self.UI_scale += 0.2
        ctk.set_widget_scaling(self.UI_scale)
        self.update_widgets()

    def zoom_out(self):
        """
        Zooms out the UI by 20%.

        Args:
            self: The instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        self.UI_scale -= 0.2
        ctk.set_widget_scaling(self.UI_scale)
        self.update_widgets()

    def zoom_reset(self):
        """
        Resets the Zoom to 100%.

        Args:
            self: The instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        self.UI_scale = 1.0
        ctk.set_widget_scaling(self.UI_scale)
        self.update_widgets()

    def update_widgets(self):
        """
        Updates specific widgets when changing scale

        Args:
            self: the instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        self.new_capture.configure(image=make_icon("images/icons/new_capture.svg", int(20*self.UI_scale)))
        self.open_capture.configure(image=make_icon("images/icons/open_capture.svg", int(20*self.UI_scale)))
        self.save_capture.configure(image=make_icon("images/icons/save_capture.svg", int(20*self.UI_scale)))
        self.start_capture.configure(image=make_icon("images/icons/start_capture.svg", int(20*self.UI_scale)))
        self.stop_capture.configure(image=make_icon("images/icons/stop_capture.svg", int(20*self.UI_scale)))
        self.edit_capture.configure(image=make_icon("images/icons/edit_capture.svg", int(20*self.UI_scale)))
        self.quit.configure(image=make_icon("images/icons/quit.svg", int(20*self.UI_scale)))
        self.about.configure(image=make_icon("images/icons/info.svg", int(20*self.UI_scale)))
        self.settings.configure(image=make_icon("images/icons/settings.svg", int(20*self.UI_scale)))
        self.filter_entry.image = svg.SvgImage(file="images/icons/search.svg", scaletoheight=int(20*self.UI_scale))
        self.filter_button.configure(image=self.filter_entry.image)

    def stop_cap(self):
        """
        Stop the capture.

        Args:
            self: the instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        # specify that sniffing has stopped
        self.is_sniffing = False
        self.stop_event.set()

        #wait for the sniffing thread to complete some work
        self.sniff_thread.join(0.9)

        # if it's still alive, kill it
        if self.sniff_thread.is_alive():
            self.sniff_thread.kill()

        # close the sniff object and the file its writing to
        self.sniffer_obj.close()

    def on_window_close(self):
        """
        Tasks to run before the program exiting, such as saving unsaved data, etc.

        Args:
            self: The instance of the Application class.

        Returns:
            None

        Raises:
            None
        """

        # if currently sniffing, stop
        if self.is_sniffing:
            self.stop_cap()

        # check if the data has been saved
        # if not, open save file dialog box
        if not self.is_saved and len(self.captured_packets) != 0:
            # print('data was not saved....') # debugging purposes
            # show save dialog box
            popup = CTkToplevel()
            popup.title("unsaved data...")
            popup.wm_attributes("-topmost", 1)

            # content of popup
            label = CTkLabel(popup, text="You have unsaved data. Do you wish to save it?")
            label.grid(row=0, column=0, columnspan=3)
            save = CTkButton(popup, text="Save Changes", command=lambda x=popup, y=True: self.save_data(x, y))
            save.grid(row=1, column=0, padx=5, pady=5)
            quita = CTkButton(popup, text="Quit Without Saving", command=lambda x=popup: self.dont_save(x))
            quita.grid(row=1, column=1, padx=5, pady=5)
            cancel = CTkButton(popup, text="Cancel", command=lambda x=popup: self.cancel(x))
            cancel.grid(row=1, column=2, padx=5, pady=5)

            popup.focus_set()
            popup.wait_window()
        # data has already been saved, safe to just exit
        else:
            self.packet_table = None
            self.destroy()

    def save_data(self, popup: CTkToplevel = None, is_closing: bool = False):
        """
        Save the capture data.

        Args:
            self: the instance of the Application class
            popup: popup, for destroying it
            is_closing: should the program close after saving

        Returns:
            None

        Raises:
            None
        """
        # destroy the popup if not None
        if popup:
            popup.destroy()

        # open a file dialog for the user (limited to .pcap or all)
        filename = filedialog.asksaveasfile(defaultextension=".pcap", filetypes=[("libpcap Files", "*.pcap"), ("All Files", "*.*")])

        # if the user specified a file, save it
        if filename:
            try:
                os.replace("temp.pcap", filename.name) # move the temporary file to the specified one
                self.is_saved = True # set saved flag

                # change ownership of the file - because the program needs to be run as root
                user = os.getlogin()                # get the current user
                uid = getpwnam(user).pw_uid         # get their user ID
                gid = getpwnam(user).pw_gid         # get their group ID
                os.chown(filename.name, uid, gid)   # perform the ownership change
            except Exception as e:
                print(e)
            # print(filename.name) # debugging purposes
            filename.close() # closing the file properly

        if is_closing: # close the program, if we got here from the quit button
            self.packet_table = None
            self.destroy()

    def dont_save(self, popup: CTkToplevel):
        """
        Close the program without saving.

        Args:
            self: the instance of the Application class
            popup: the popup, for destroying

        Returns:
            None

        Raises:
            None
        """
        os.remove("temp.pcap")  # remove the temporary capture
        # close the program
        popup.destroy()
        self.destroy()

    def cancel(self, popup: CTkToplevel):
        """
        The user changed their mind about quiting without saving.

        Args:
            self: the instance of the Application class
            popup: the popup, for destroying

        Returns:
            None

        Raises:
            None
        """
        popup.destroy()

    def new_cap(self):
        """
        Start a new capture, and delete the old 'session'.

        Args:
            self: the instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        # create a new table instance, over the old one
        self.packet_table = Table(self.packet_scroll, 0, 0, "nsew", 0, 0, values=[self.headers])
        # reset the packet list
        self.captured_packets = []
        # switch the save status of the application
        self.is_saved = False
        # remove the old tep file, if it exists
        if os.path.exists("temp.pcap"):
            os.remove("temp.pcap")
        # show the interface popup, same one as when starting the application
        self.show_interface_popup()

    def open_cap(self):
        """
        Opens a previously saved .pcap file

        Args:
            self: instance of the Application class

        Returns:
            None

        Raises:
            None
        """
        # get the filepath of the file
        filename = filedialog.askopenfile(defaultextension=".pcap", filetypes=[("libpcap Files", "*.pcap"), ("All Files", "*.*")])
        # print(filename.name) # debug purposes

        # reset the table (especially if a new session was made)
        self.packet_table = Table(self.packet_scroll, 0, 0, "nsew", 0, 0, values=[self.headers])
        # reset the packet list
        self.captured_packets = []
        # set save state to true
        self.is_saved = True

        # if the user actually selected a file
        if filename:
            # use pylibpcap to read the data of the file
            # and save it into the captured_packets list
            for leng, t, pkt in rpcap(filename.name):
                self.captured_packets.append(dict(timestamp=t, packet_length=len, data=pkt))  # add packet to dictionary array
                # print(f"Length: {leng}\nTimestamp: {t}\nData: {pkt}") #debugging purposes

                # unpack the ethernet frame
                dest_mac, src_mac, eth_type, packet_data = unpack_frame(pkt)

                # check if the source MAC and/or dest MAc are not all zeros
                # disregards all localhost traffic
                if (sum(src_mac) != 0 or sum(dest_mac) != 0) and self.filter_local:
                    # unpack an ARP packet
                    if eth_type == 2054:
                        hw_type, proto_type, hw_len, proto_len, op_code, send_hw, send_proto, target_hw, target_proto = unpack_arp(packet_data)
                        self.packet_table.add_row([str(len(self.captured_packets)), t, leng, format_ip(send_proto), format_ip(target_proto), "n/a", "n/a", get_eth_str('0x' + '{:04x}'.format(eth_type).upper()), None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))
                    # unpack IPv6 packet
                    elif eth_type == 34525:
                        version, traffic_class, flow_label, payload_length, next_header, hop_limit, ip6_src, ip6_dst, ipv6_payload = unpack_ipv6(packet_data)
                        self.packet_table.add_row([str(len(self.captured_packets)), t, leng, form_ipv6_addr(ip6_src), form_ipv6_addr(ip6_dst), "n/a", "n/a", get_eth_str('0x' + '{:04x}'.format(eth_type).upper()), None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))
                    # unpack IPv4 packet:
                    elif eth_type == 2048:
                        version, ihl, dscp, ecn, total_length, identification, flags, frag_off, ttl, protocol, head_check, ip4_src, ip4_dst, ipv4_payload = unpack_ipv4(packet_data)
                        proto_abbr, proto_name, proto_ref, code = get_ip_protocol('0x' + '{:02x}'.format(protocol).upper())

                        # unpack ICMP (0x01) - protocol
                        if protocol == 1:
                            type_code, subtype_code, icmp_checksum, icmp_data = unpack_icmp(ipv4_payload)
                            icmp_type, icmp_subtype, icmp_type_status, ret_code = get_icmp_type(str(type_code),str(subtype_code))
                            self.packet_table.add_row([str(len(self.captured_packets)), t, leng, format_ip(ip4_src), format_ip(ip4_dst), "n/a", "n/a", proto_name, None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))
                        # unpack TCP/IP packet (ox06) - protocol
                        elif protocol == 6:
                            src_port, dst_port, sequence_num, ack_num, data_offset, reserved, flags, window, tcp_checksum, upointer, tcp_data = unpack_tcp(ipv4_payload)
                            self.packet_table.add_row([str(len(self.captured_packets)), t, leng, format_ip(ip4_src), format_ip(ip4_dst), src_port, dst_port, proto_name, None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))
                        # unpack UDP packet (0x11) - protocol
                        elif protocol == 17:
                            src_port, dst_port, length, udp_checksum, udp_data = unpack_udp(ipv4_payload)
                            self.packet_table.add_row([str(len(self.captured_packets)), t, leng, format_ip(ip4_src), format_ip(ip4_dst), src_port, dst_port, proto_name, None], lambda i=len(self.captured_packets): self.handle_table_button_click(i))



# the 'main' function
if __name__ == "__main__":
    app = Application()
    app.protocol("WM_DELETE_WINDOW", app.on_window_close)
    app.mainloop()