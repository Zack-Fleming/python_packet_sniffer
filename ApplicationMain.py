# import(s)
# main GUI libraries
import os
import threading
import tkinter as tk
import customtkinter as ctk
from PyThreadKiller import PyThreadKiller
from customtkinter import CTkButton, CTkToplevel, CTkLabel, filedialog, CTkTextbox
from pylibpcap import get_iface_list
from pylibpcap.base import Sniff
# additional libraries for GUI
from tktooltip import ToolTip
# misc. libraries
from utility.photo_functions import *
from scapy.all import get_if_list
from utility.sniffer import *
from utility.Table import *
from utility.sniffer_data_sets import get_ip_protocol, get_icmp_type

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
        self.menu_bar = ctk.CTkFrame(self, height=40)
        self.menu_bar.grid(row=0, column=0, pady=0, sticky="new")

        # add the buttons to the menu bar
        # capture file operations
        self.new_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/new_capture.svg", self.menu_bar._current_height-20), text="", corner_radius=0, width=30, command=self.new_capture)
        ToolTip(self.new_capture, msg="New Capture", delay=0.5)
        self.new_capture.pack(side=tk.LEFT, padx=5)
        self.open_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/open_capture.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.open_capture, msg="Open Capture", delay=0.5)
        self.open_capture.pack(side=tk.LEFT)
        self.save_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/save_capture.svg", 20), text="", corner_radius=0, width=30, command=lambda x=None: self.save_data(x))
        ToolTip(self.save_capture, msg="Save Capture", delay=0.5)
        self.save_capture.pack(side=tk.LEFT, padx=5)
        # data capture operations
        self.start_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/start_capture.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.start_capture, msg="Start Capture", delay=0.5)
        self.start_capture.pack(side=tk.LEFT, padx=5)
        self.stop_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/stop_capture.svg", 20), text="", corner_radius=0, width=30, command=self.stop_cap)
        ToolTip(self.stop_capture, msg="Stop Capture", delay=0.5)
        self.stop_capture.pack(side=tk.LEFT)
        self.edit_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/edit_capture.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.edit_capture, msg="Edit Capture", delay=0.5)
        self.edit_capture.pack(side=tk.LEFT, padx=5)
        # misc operations
        self.quit = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/quit.svg", 20), text="", corner_radius=0, width=30, command=self.on_window_close)
        ToolTip(self.quit, msg="Quit", delay=0.5)
        self.quit.pack(side=tk.RIGHT, padx=5)
        self.about = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/info.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.about, msg="About", delay=0.5)
        self.about.pack(side=tk.RIGHT)
        self.settings = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/settings.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.settings, msg="Settings", delay=0.5)
        self.settings.pack(side=tk.RIGHT, padx=5)
        # filter search bar
        self.filter_frame = ctk.CTkFrame(self.menu_bar)
        self.filter_frame.pack(side=tk.LEFT, padx=5)
        self.filter_entry = ctk.CTkEntry(self.filter_frame, width=self._current_width/10, corner_radius=0)
        self.filter_entry.image = svg.SvgImage(file="images/icons/search.svg", scaletoheight=20)
        self.filter_entry.pack(side=tk.LEFT)
        self.filter_button = ctk.CTkButton(self.filter_frame, image=self.filter_entry.image, text="", width=30, corner_radius=0)
        self.filter_button.pack(side=tk.LEFT, fill="y")

        # packet list pane/table
        self.packet_scroll = ctk.CTkScrollableFrame(self)
        self.packet_scroll.grid(row=1, column=0, pady=0, sticky="nsew")
        self.packet_scroll.grid_columnconfigure(0, weight=1)
        # table of captured packets
        # self.packet_table = CTkTable(master=self.packet_scroll, column=len(self.headers))
        # self.packet_table.add_row(self.headers, index=0)
        # self.packet_table.grid(row=0, column=0, pady=0, sticky="nsew")
        self.packet_table = Table(self.packet_scroll, 0, 0, "nsew", 0, 0, values=[self.headers])

        # data view pane
        self.data_view_pane = ctk.CTkFrame(self)
        self.data_view_pane.grid(row=2, column=0, pady=0, sticky="nsew")
        self.data_view_pane.grid_columnconfigure((0, 1), weight=1)
        self.data_view_pane.grid_rowconfigure(0, weight=1)
        # text data view
        self.text_pane = ctk.CTkScrollableFrame(self.data_view_pane, label_text="ASCII Packet Data")
        self.text_pane.grid(row=0, column=0, pady=0, sticky="nsew")
        self.ascii_text = CTkLabel(self.text_pane, text="test")
        self.ascii_text.grid(row=0, column=0, sticky="nsew")
        # hex/bin data view
        self.hex_bin_view = ctk.CTkScrollableFrame(self.data_view_pane, label_text="HEX/BIN Packet Data")
        self.hex_bin_view.grid(row=0, column=1, pady=0, sticky="nsew")
        self.hex_bin_text = CTkLabel(self.hex_bin_view, text="Hexdump:")
        self.hex_bin_text.grid(row=0, column=0, sticky="nsew")



    def show_interface_popup(self):
        """
        Shows the popup that has the user choose the interface being used for sniffing.

        Args:
            self: instance of the Application class

        Returns:
            The chosen interface name as a str

        Raises:
            None
        """
        popup = ctk.CTkToplevel()
        popup.title("Select Network Interface")
        popup.wm_attributes("-topmost", 1)

        popup_label = ctk.CTkLabel(popup, text="Select the network interface to listen on:")
        popup_label.pack()

        interfaces = get_iface_list()
        # print(interfaces) # debug purposes

        for interface in interfaces:
            button = ctk.CTkButton(popup, text=interface, command=lambda x=interface, y=popup: self.set_current_interface(x, y))
            button.pack(pady=5)

        popup.grab_set()
        popup.focus_set()
        popup.wait_window()


    def set_current_interface(self, name: str, popup: CTkToplevel):
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
        while self.is_sniffing:
            protocol = src_port = dst_port = proto_name = ip4_src = ip4_dst = ip6_src = ip6_dst = None
            for plen, t, buf in self.sniffer_obj.capture():
                self.captured_packets.append(buf) # add packet to array

                # unpack the ethernet frame
                dest_mac, src_mac, eth_type, packet_data = unpack_frame(buf)

                # check if the source MAC and/or dest MAc are not all zeros
                # disregards all localhost traffic
                if (sum(src_mac) !=0 or sum(dest_mac)) and self.filter_local:
                    # unpack an ARP packet
                    if eth_type == 2054:
                        hw_type, proto_type, hw_len, proto_len, op_code, send_hw, sned_proto, target_hw, target_proto = unpack_arp(packet_data)
                    # unpack IPv6 packet
                    elif eth_type == 34525:
                        version, traffic_class, flow_label, payload_length, next_header, hop_limit, ip6_src, ip6_dst, ipv6_payload = unpack_ipv6(packet_data)
                    # unpack IPv4 packet:
                    elif eth_type == 2048:
                        version, ihl, dscp, ecn, total_length, identification, flags, frag_off, ttl, protocol, head_check, ip4_src, ip4_dst, ipv4_payload = unpack_ipv4(packet_data)
                        proto_abbr, proto_name, proto_ref, code = get_ip_protocol('0x' + '{:02x}'.format(protocol).upper())

                        # unpack ICMP (0x01) - protocol
                        if protocol == 1:
                            type_code, subtype_code, icmp_checksum, icmp_data = unpack_icmp(ipv4_payload)
                            icmp_type, icmp_subtype, icmp_type_status, ret_code = get_icmp_type(str(type_code), str(subtype_code))
                        # unpack TCP/IP packet (ox06) - protocol
                        elif protocol == 6:
                            rc_port, dst_port, sequence_num, ack_num, data_offset, reserved, flags, window, tcp_checksum, upointer, tcp_data = unpack_tcp(ipv4_payload)
                        # unpack UDP packet (0x11) - protocol
                        elif protocol == 17:
                            src_port, dst_port, length, udp_checksum, udp_data = unpack_udp(ipv4_payload)



                    self.packet_table.add_row([str(len(self.captured_packets)),
                                               t,
                                               plen,
                                               format_ip(ip4_src) if ip4_src is not None and eth_type == 2048 else form_ipv6_addr(ip6_src) if ip6_src is not None and eth_type == 34525 else "n/a",
                                               format_ip(ip4_dst) if ip4_dst is not None and eth_type == 2048 else form_ipv6_addr(ip6_dst) if ip6_dst is not None and eth_type == 34525 else "n/a",
                                               src_port if protocol is not None and ((protocol == 6) or (protocol == 17)) else "n/a",
                                               dst_port if protocol is not None and ((protocol == 6) or (protocol == 17)) else "n/a",
                                               proto_name if proto_name is not None else "n/a",
                                               None],
                                              lambda i=len(self.captured_packets): self.set_data_panes(i))


    def set_data_panes(self, index: int):
        new_text = "Packet Data:\n" + "\n\ninputted packet index: " + str(index) + "\npacket data: " + str(self.captured_packets[index])


        # set the text of the label
        self.ascii_text.configure(text=new_text)


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
        self.is_sniffing = False
        self.sniff_thread.kill()


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

        if self.is_sniffing:
            self.stop_cap()

        # check if the data has been saved
        # if not, open save file dialog box
        if not self.is_saved and len(self.captured_packets) != 0:
            print('data was not saved....')
            # show save dialog box
            popup = ctk.CTkToplevel()
            popup.title("unsaved data...")
            popup.wm_attributes("-topmost", 1)

            # content of popup
            label = CTkLabel(popup, text="You have unsaved data. Do you wish to save it?")
            label.grid(row=0, column=0, columnspan=3)
            save = CTkButton(popup, text="Save Changes", command=lambda x=popup: self.save_data(x))
            save.grid(row=1, column=0)
            quita = CTkButton(popup, text="Quit Without Saving", command=lambda x=popup: self.dont_save(x))
            quita.grid(row=1, column=1)
            cancel = CTkButton(popup, text="Cancel", command=lambda x=popup: self.cancel(x))
            cancel.grid(row=1, column=2)

            popup.focus_set()
            popup.wait_window()
        # data has already been saved, safe to just exit
        else:
            self.destroy()


    def save_data(self, popup: CTkToplevel):
        if popup:
            popup.destroy()

        filename = filedialog.asksaveasfile(defaultextension=".pcap", filetypes=[("libpcap Files", "*.pcap"), ("All Files", "*.*")])

        if filename:
            try:
                os.replace("temp.pcap", filename.name)
                self.is_saved = True # set saved flag
            except Exception as e:
                print(e.with_traceback())
        print(filename.name)
        filename.close()


    def dont_save(self, popup: CTkToplevel):
        popup.destroy()
        self.destroy()


    def cancel(self, popup: CTkToplevel):
        popup.destroy()


    def new_capture(self):
        self.packet_table = Table(self.packet_scroll, 0, 0, "nsew", 0, 0, values=[self.headers])
        self.captured_packets = []
        self.is_saved = False
        if os.path.exists("temp.pcap"):
            os.remove("temp.pcap")
        self.show_interface_popup()


    def open_capture(self):
        pass





# the 'main' function
if __name__ == "__main__":
    app = Application()
    app.protocol("WM_DELETE_WINDOW", app.on_window_close)
    app.mainloop()