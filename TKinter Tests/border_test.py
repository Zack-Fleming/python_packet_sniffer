import customtkinter

root = customtkinter.CTk()
root.title("Grid with Border Example")

# Create a CTkFrame with a border
frame = customtkinter.CTkFrame(master=root, border_width=2, border_color="white")
frame.grid(row=0, column=0, padx=10, pady=10)  # Add padding around the frame

# Place widgets inside the frame using grid
label1 = customtkinter.CTkLabel(master=frame, text="Label 1")
label1.grid(row=0, column=0, padx=5, pady=5)

label2 = customtkinter.CTkLabel(master=frame, text="Label 2")
label2.grid(row=0, column=1, padx=5, pady=5)

button1 = customtkinter.CTkButton(master=frame, text="Button 1")
button1.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

root.mainloop()