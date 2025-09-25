import tkinter as tk
from tkinter import ttk, simpledialog

class ContactView(ttk.Frame):
    def __init__(self, parent, rename_callback, select_callback):
        super().__init__(parent, padding=10)
        self.rename_callback = rename_callback
        self.select_callback = select_callback

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # --- Widgets ---
        container = ttk.LabelFrame(self, text="Discovered Machines")
        container.grid(sticky="nsew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.contact_listbox = tk.Listbox(container, width=40, font=("Helvetica", 12))
        self.contact_listbox.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.contact_listbox.bind("<Double-1>", self._on_select)

        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.contact_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.contact_listbox.config(yscrollcommand=scrollbar.set)

        rename_btn = ttk.Button(container, text="Rename Selected", command=self._on_rename)
        rename_btn.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=(0, 5))

    def update_list(self, contacts, self_mac):
        """Refreshes the contact listbox."""
        current_selection = self.contact_listbox.curselection()
        
        self.contact_listbox.delete(0, tk.END)
        
        # Store MACs to retrieve them later by index
        self._mac_map = []
        
        sorted_macs = sorted(contacts.keys(), key=lambda m: contacts[m] == "Me", reverse=True)
        
        for mac in sorted_macs:
            name = contacts[mac]
            display_text = f"{name} ({mac})"
            if mac == self_mac:
                display_text += " [You]"
            
            self.contact_listbox.insert(tk.END, display_text)
            self._mac_map.append(mac)
            if mac == self_mac:
                self.contact_listbox.itemconfig(tk.END, {'fg': 'blue'})

        # Restore selection if possible
        if current_selection:
            self.contact_listbox.selection_set(current_selection)

    def _on_rename(self):
        selection_index = self.contact_listbox.curselection()
        if not selection_index:
            return
        
        mac_to_rename = self._mac_map[selection_index[0]]
        self.rename_callback(mac_to_rename)

    def _on_select(self, event=None):
        selection_index = self.contact_listbox.curselection()
        if not selection_index:
            return
        
        mac_to_chat = self._mac_map[selection_index[0]]
        self.select_callback(mac_to_chat)