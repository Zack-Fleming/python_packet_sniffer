from tkinter import *

# create root window
root = Tk()

# settings of the window
root.minsize(640, 480)

# define component(s)
label = Label(root, text="it's alive")

# add component(s) to window
label.grid(row=0, column=0)


root.mainloop()