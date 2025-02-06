from tkinter import *


# button events
def clicked_q():
    Label(root, text="I stole thy time...").pack()


# create root window
root = Tk()

# settings of the window
root.minsize(640, 480)

# define component(s)
# fg - text color; bg - background color;
label = Label(root, text="Click below: v")
# activeforeground - hover/click foreground; activebackground - hover/click background
button = Button(root, text="Click ME!!!!", padx=10, pady=10, command=clicked_q, activebackground="#ff0000", activeforeground="#0000ff")

# add component(s) to window
label.pack()
button.pack()


root.mainloop()