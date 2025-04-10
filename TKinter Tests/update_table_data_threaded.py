import customtkinter
import threading
import queue
import time


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.table_data = []
        self.data_queue = queue.Queue()

        self.table = customtkinter.CTkTextbox(self)
        self.table.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        self.start_button = customtkinter.CTkButton(self, text="Start Update", command=self.start_update_thread)
        self.start_button.grid(row=1, column=0, padx=20, pady=20, sticky="ew")

    def start_update_thread(self):
        threading.Thread(target=self.update_data, daemon=True).start()
        self.after(100, self.check_queue)

    def update_data(self):
        for i in range(5):
            time.sleep(1)
            self.data_queue.put([f"Row {i + 1}", f"Value {i + 1}"])

    def check_queue(self):
        try:
            data = self.data_queue.get_nowait()
            self.table_data.append(data)
            self.update_table()
        except queue.Empty:
            pass
        self.after(100, self.check_queue)

    def update_table(self):
        self.table.delete("0.0", "end")
        for row in self.table_data:
            self.table.insert("end", "\t".join(row) + "\n")


if __name__ == "__main__":
    app = App()
    app.mainloop()