# import(s)
import tkinter as tk

import customtkinter as ctk
import tksvg as svg
import xml.etree.ElementTree as ET

# setting default/startup theme and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# Application class
class Application(ctk.CTk):
    # flag for if the captured data is saved
    # open the 'save before exiting' dialog window
    is_saved = False
    # keeps track of the currently opened/saved file
    current_file = None
    # keep track of the pressed state of keys
    pressed_keys = {}
    # keep track of the current UI scale
    UI_scale = None

    def __init__(self):
        super().__init__() # call the init of the 'inherited class'

        # add a binding to handle keybinds
        self.bind("<KeyPress>", self.on_key_press)
        self.bind("<KeyRelease>", self.on_key_release)

        # get the current UI scaling
        self.UI_scale = ctk.ScalingTracker.get_widget_scaling(self)

        # configure window settings
        self.title("Python Packet Sniffer")
        self.geometry("1280x720")

        # configuring the grid layout (3x1) (row x column)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # setup program font(s)
        # monospace for hex and binary view(s)
        mono_space = ("Fira Code", 21)

        # create the menu bar
        self.menu_bar = ctk.CTkFrame(self, height=40)
        self.menu_bar.grid(row=0, column=0, pady=0, sticky="new")

        # add the buttons to the menu bar
        self.button = ctk.CTkButton(self.menu_bar, image=self.make_icon("images/icons/settings.svg", 20), text="testing")
        self.button.pack()

    # set the state of the key to True
    def on_key_press(self, event):
        self.pressed_keys[event.keysym] = True
        # print(f'Key: {event.keysym}') # debugging purposes
        self.handle_key_press()


    # set the state of the key to False
    def on_key_release(self, event):
        self.pressed_keys[event.keysym] = False
        self.handle_key_press()

    # handle the key press(es)
    def handle_key_press(self):
        # Ctrl + Q = quit
        if (self.pressed_keys.get("Control_L") or self.pressed_keys.get("Control_R")) and self.pressed_keys.get("q"):
            self.on_window_close()
        if self.pressed_keys.get("Control_L") and self.pressed_keys.get("Shift_L") and self.pressed_keys.get("plus"):
            self.zoom_in()
        if self.pressed_keys.get("Control_L") and self.pressed_keys.get("Shift_L") and self.pressed_keys.get("underscore"):
            self.zoom_out()
        if self.pressed_keys.get("Control_L") and self.pressed_keys.get("Shift_L") and self.pressed_keys.get("parenright"):
            self.zoom_reset()

    # function for closing the window
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
        # check if the data has been saved
        # if not, open save file dialog box
        if not self.is_saved:
            print('data was not saved....')

        # dispose of window resources more gracefully
        self.destroy()

    # load an SVG to be used as an ICON image
    def make_icon(self, path: str, size: int):
        """
        Loads an SVG image to be used as an ICON image.

        Args:
            self: The instance of the Application class
            path: (String) path of the SVG image
            size: (int32) The height to scale the SVG to

        Returns:
            (tksvg.SvgImage) The loaded SVG image.

        Raises:
            When used in CTkLabel or CTkButton, raises a warning about receiving a different Image instance.
        """
        svg_im = svg.SvgImage(file=path, scaletoheight=size)
        return svg_im

    # change the fill tag in a SVG
    # path
    def svg_change_fill(self, path: str, color: str):
        """
        Changes the fill color of an SVG. Used to keep the icons the same color as the text color of hte application theme.

        Args:
            self: The instance of the Application class
            path: (String) path of the SVG image
            color: (String) color name or Hex string of color

        Returns:
            None

        Raises:
            None
        """
        ET.register_namespace("", "http://www.w3.org/2000/svg")
        tree = ET.parse(path)
        root = tree.getroot()
        root.attrib["fill"] = color
        tree.write(path)

    # 'zoom in' the UI
    def zoom_in(self):
        self.UI_scale += 0.2
        ctk.set_widget_scaling(self.UI_scale)

    # 'zoom out' the UI
    def zoom_out(self):
        self.UI_scale -= 0.2
        ctk.set_widget_scaling(self.UI_scale)

    # reset zoom the UI
    def zoom_reset(self):
        self.UI_scale = 1.0
        ctk.set_widget_scaling(self.UI_scale)


# the 'main' function
if __name__ == "__main__":
    app = Application()
    app.protocol("WM_DELETE_WINDOW", app.on_window_close)
    app.mainloop()