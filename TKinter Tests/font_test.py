from tkinter import font
import customtkinter as ctk
from customtkinter import CTkLabel


class FontTest(ctk.CTk):
    font_list = []

    def __init__(self):
        super().__init__()

        # setup window preferences
        self.title("Fonts Test")
        self.geometry("1000x700")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # get sorted list of unique font names
        self.font_list = [s.lower() for s in set(font.families())]
        self.font_list.sort()

        # crete a scroll pane to put the list of labels on
        self.scroll_pane = ctk.CTkScrollableFrame(self, label_text="Fonts List:")
        self.scroll_pane.grid(row=0, column=0, sticky="nsew")

        # add a label for every font in the font list
        for i in range(len(self.font_list)):
            font_name = CTkLabel(master=self.scroll_pane, text=f"{self.font_list[i]}:", font=("arial", 15))
            font_name.grid(column=0, row=i)
            label = ctk.CTkLabel(master=self.scroll_pane, text="The quick brown fox jumped over the lazy dog.", font=(self.font_list[i], 15))
            label.grid(column=1, row=i)


    def on_close(self):
        self.destroy()


# root = Tk()
#
# # list of fonts
# font_list = [s.lower() for s in list(set(list(font.families())))]
# font_list.sort()

app = FontTest()
app.protocol("WM_DELETE_WINDOW", app.on_close)
app.mainloop()