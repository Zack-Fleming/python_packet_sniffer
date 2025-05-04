import tkinter
import customtkinter
from customtkinter import CTkFrame, CTkScrollableFrame, CTkButton


class Table(CTkFrame):
    def __init__(
            self,
            parent: CTkFrame | CTkScrollableFrame,
            parent_row: int = 0,
            parent_col: int = 0,
            sticky: str = None,
            px: int = 0,
            py: int = 0,
            row: int = None,
            col: int = None,
            values: list = None,
            fg: str = None,
            bg: str = None,
            colors: list = [None, None],
            **kwargs):
        """
        Initializes an instance of the Table class.

        Args:
            self: instance of the Table class
            parent: CTKFrame - reference to the parent frame
            row: int - number of rows to initialize
            col: int - number of columns to initialize
            values: list - data to add to the table on initialization
            fg: str - HEX code for the text color
            bg: str - HEx color code for the background

        Returns:
            The created table instance

        Raises:
            None
        """

        super().__init__(parent, **kwargs)

        # if no values were inputted, default to 2x3 table
        if values is None:
            values = [[1, 2, 3], [1, 2, 3]]

        # setup parameters for table
        self.values = values
        self.data = []
        self.rows = row if row else len(values)
        self.cols = col if col else len(values[0])
        self.num_rows = 0
        # setup colors
        self.text_color = customtkinter.ThemeManager.theme["CTkLabel"]["text_color"] if fg is None else fg
        self.border_color = customtkinter.ThemeManager.theme["CTkLabel"]["text_color"] if fg is None else fg
        self.tagged_colors_list = None

        # base frame of the table
        self.grid(row=parent_row, column=parent_col, padx=px, pady=py, sticky=sticky)
        self.grid_columnconfigure(index=tuple(range(self.cols)), weight=1)
        #self.configure(fg_color="#ff0000")

        # draw the table with initial data
        for value in values:
            self.add_row(value)

    def add_row(self, values: list, command: () = None):
        # add the row. only if the number of columns match
        if len(values) == self.cols:
            self.data.append(values)
            # fill the row with the data
            for i in range(len(values) - (1 if self.num_rows != 0 else 0)):
                cell = tkinter.Label(self, text=values[i], background=("#2b2b2b" if self.num_rows % 2 == 0 else "#242424"), fg="#ffffff")
                #cell = CTkLabel(self, text=values[i])
                cell.grid(column=i, row=self.num_rows, sticky="we")

            # add the additional button, only on non-header rows
            if self.num_rows != 0:
                btn = CTkButton(self, text="packet: " + str(self.num_rows), corner_radius=0, command=command)
                btn.grid(column=self.cols-1, row=self.num_rows, sticky="we")

            # increment current row counter
            self.num_rows += 1
        # do not add row, if the number of cols do not match
        else:
            raise ValueError("error: the number of inputted columns do not mach expected...")