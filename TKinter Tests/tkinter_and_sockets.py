import tkinter as tk
import socket
import threading


class App:
    def __init__(self, master):
        self.master = master
        master.title("Socket Data Receiver")

        self.label_text = tk.StringVar()
        self.label_text.set("Waiting for data...")
        self.label = tk.Label(master, textvariable=self.label_text)
        self.label.pack()

        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        self.thread = threading.Thread(target=self.receive_data, daemon=True)
        self.thread.start()

    def receive_data(self):
        while True:
            data, addr = self.sock.recvfrom(65535)
            if data:
                self.master.after(0, self.update_label, data)

    def update_label(self, data):
        self.label_text.set(f"Received: {data}\n")

    def close_connection(self):
        self.sock.close()
        self.master.destroy()


root = tk.Tk()
app = App(root)
root.protocol("WM_DELETE_WINDOW", app.close_connection)  # Close socket on window close
root.mainloop()