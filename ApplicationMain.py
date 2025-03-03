# import(s)
# main GUI libraries
import multiprocessing
import threading
import tkinter as tk
import customtkinter as ctk
from PyThreadKiller import PyThreadKiller
from customtkinter import CTkButton, CTkToplevel
from pylibpcap import get_iface_list
from pylibpcap.base import Sniff
from scapy.sendrecv import sniff
# additional libraries for GUI
from tktooltip import ToolTip
from CTkTable import *
# misc. libraries
from utility.photo_functions import *
from scapy.all import get_if_list

# setting default/startup theme and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# Application class
class Application(ctk.CTk):
    # flag for if the captured data is saved
    # open the 'save before exiting' dialog window
    is_saved = False
    # flag for if currently sniffing packets
    is_sniffing = False
    # keeps track of the currently opened/saved file
    current_file = None
    # keep track of the pressed state of keys
    pressed_keys = {}
    # keep track of the current UI scale
    UI_scale = None
    # the sniffer object
    sniffer_obj = None
    # thread to do the sniffing
    sniff_thread = None
    # keeps track of the captures packets
    captured_packets = [] # use len() + 1 for table index
    # interface listening on
    interface = None
    # keep track of the column headers for packet table
    headers = ["Timestamp", "Packet Len.", "Src. Mac", "Dest. Mac", "Src. IP", "Dest. IP", "Src Port", "Dest Port", "Protocol"]

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
        self.new_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/new_capture.svg", self.menu_bar._current_height-20), text="", corner_radius=0, width=30)
        ToolTip(self.new_capture, msg="New Capture", delay=0.5)
        self.new_capture.pack(side=tk.LEFT, padx=5)
        self.open_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/open_capture.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.open_capture, msg="Open Capture", delay=0.5)
        self.open_capture.pack(side=tk.LEFT)
        self.save_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/save_capture.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.save_capture, msg="Save Capture", delay=0.5)
        self.save_capture.pack(side=tk.LEFT, padx=5)
        # data capture operations
        self.start_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/start_capture.svg", 20), text="", corner_radius=0, width=30)
        ToolTip(self.start_capture, msg="Start Capture", delay=0.5)
        self.start_capture.pack(side=tk.LEFT, padx=5)
        self.stop_capture = ctk.CTkButton(self.menu_bar, image=make_icon("images/icons/stop_capture.svg", 20), text="", corner_radius=0, width=30, command=self.stop_capture)
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
        self.packet_table = CTkTable(master=self.packet_scroll, column=len(self.headers))
        self.packet_table.add_row(self.headers, index=0)
        self.packet_table.grid(row=0, column=0, pady=0, sticky="nsew")

        # data view pane
        self.data_view_pane = ctk.CTkFrame(self)
        self.data_view_pane.grid(row=2, column=0, pady=0, sticky="nsew")
        self.data_view_pane.grid_columnconfigure((0, 1), weight=1)
        self.data_view_pane.grid_rowconfigure(0, weight=1)
        # text data view
        self.text_pane = ctk.CTkScrollableFrame(self.data_view_pane, label_text="ASCII Packet Data")
        self.text_pane.grid(row=0, column=0, pady=0, sticky="nsew")

        # hex/bin data view
        self.hex_bin_view = ctk.CTkScrollableFrame(self.data_view_pane, label_text="HEX/BIN Packet Data")
        self.hex_bin_view.grid(row=0, column=1, pady=0, sticky="nsew")


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
        print(interfaces)

        for interface in interfaces:
            button = ctk.CTkButton(popup, text=interface, command=lambda x=interface, y=popup: self.set_current_interface(x, y))
            button.pack(pady=5)

        popup.grab_set()
        popup.focus_set()
        popup.wait_window()


    def set_current_interface(self, name: str, popup: CTkToplevel):
        self.interface = name
        self.is_sniffing = True
        popup.destroy()
        self.sniffer_obj = Sniff(self.interface, count=-1, promisc=1)
        self.sniff_thread = PyThreadKiller(target=self.sniff)
        self.sniff_thread.start()

    def sniff(self):
        while self.is_sniffing:
            for plen, t, buf in self.sniffer_obj.capture():
                print("\n\n[+]: Payload len=", plen)
                print("[+]: Time", t)
                self.captured_packets.append(buf)
                #print("[+]: Payload", buf)
                self.packet_table.add_row([t, plen], index=len(self.captured_packets))


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
        self.is_sniffing = False

        # check if the data has been saved
        # if not, open save file dialog box
        if not self.is_saved:
            print('data was not saved....')

        # dispose of window resources more gracefully
        self.destroy()


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


    def stop_capture(self):
        self.is_sniffing = False
        self.sniff_thread.kill()


# the 'main' function
if __name__ == "__main__":
    app = Application()
    app.protocol("WM_DELETE_WINDOW", app.on_window_close)
    app.mainloop()