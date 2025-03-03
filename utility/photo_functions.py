import random
from PIL import Image, ImageTk
import tksvg as svg
import xml.etree.ElementTree as ET

# select a random icon image for the taskbar and ico
def make_app_icon():
    """

    :return:
    """
    images = [
        "images/icons/ethernet-solid.ico",
        "images/icons/lock-open-solid.ico",
        "images/icons/network-wired-solid.ico",
        "images/icons/shield-halved-solid.ico",
        "images/icons/wifi-solid.ico"
    ]
    return ImageTk.PhotoImage(Image.open(random.choice(images)))

# load an SVG to be used as an ICON image
def make_icon(path: str, size: int):
    """
    Loads an SVG image to be used as an ICON image.

    Args:
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
def svg_change_fill(path: str, color: str):
    """
    Changes the fill color of an SVG. Used to keep the icons the same color as the text color of hte application theme.

    Args:
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