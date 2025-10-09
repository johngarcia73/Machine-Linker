import tkinter as tk
from tkinter import ttk, simpledialog, messagebox,filedialog
import queue
import os
from connections import Machine
from .views.contact_view import ContactView
from .views.chat_view import ChatView
import time
from time import sleep
import threading
import struct
import zlib

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("P2P Link-Layer Messenger")
        self.geometry("850x600")
        self.minsize(700, 500)

        self.machine: Machine | None = None
        self.message_queue = queue.Queue()
        self.contacts = {}  # {mac: name}
        self.chat_histories = {} # {mac: [{"sender_display": str, "text": str, "is_self": bool}]}
        self.current_chat_mac = None
        self.current_view = None

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_config_bar()
        self._build_status_bar()

        # --- Views ---
        self.contact_view = ContactView(self, self._rename_contact, self.switch_to_chat_view)
        self.chat_view = ChatView(self, self._send_message, self._send_file, self.switch_to_contact_view)

        self.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.after(100, self._process_queue)
        
        self.switch_to_contact_view()

    def send_broadcast_message(self, msg_text):
        if not self.machine: return
        payload = b"BROADCAST:" + msg_text.encode()
        self.machine.send_frame("ff:ff:ff:ff:ff:ff", payload, self.machine.FLAG_SPEAK)
        self.contact_view.add_broadcast_message("You", msg_text)

    def _handle_incoming_message(self, src_mac, payload: bytes):
        if payload.startswith(b"BROADCAST:"):
            text = payload[10:].decode(errors="ignore")
            sender_name = self.contacts.get(src_mac, src_mac)
            self.contact_view.add_broadcast_message(sender_name, text)
        elif payload.startswith(b"TXT:"):
            text = payload[4:].decode(errors="ignore")
            sender_name = self.contacts.get(src_mac, src_mac)
            self._add_to_history(src_mac, sender_name, text, False)
            if src_mac != self.current_chat_mac:
                self.status_var.set(f"New message from {sender_name}")

        elif payload.startswith(b"FILE:"):
            header, file_content = payload[5:].split(b"::", 1)
            filename = header.decode(errors="ignore")
            sender_name = self.contacts.get(src_mac, src_mac)
            
            self.status_var.set(f"Incoming file '{filename}' from {sender_name}.")
            self._add_to_history(src_mac, "System", f"File received: '{filename}'.", False)
            
            self.after(100, lambda: self._prompt_save_file(filename, file_content))


    def _build_config_bar(self):
        frame = ttk.Frame(self, padding="5")
        frame.grid(row=0, column=0, sticky="ew")
        # ... (same as your previous version)
        ttk.Label(frame, text="Interface:").pack(side="left", padx=(0, 5))
        interfaces = ["Select..."] + Machine.list_interfaces()
        self.iface_var = tk.StringVar(value=interfaces[1] if len(interfaces) > 1 else interfaces[0])
        self.iface_combo = ttk.Combobox(frame, textvariable=self.iface_var, values=interfaces, state="readonly", width=15)
        self.iface_combo.pack(side="left", padx=5)
        ttk.Label(frame, text="Ethertype:").pack(side="left", padx=(10, 5))
        self.ethertype_var = tk.StringVar(value="0x1234")
        self.ethertype_entry = ttk.Entry(frame, textvariable=self.ethertype_var, width=10)
        self.ethertype_entry.pack(side="left", padx=5)
        self.start_btn = ttk.Button(frame, text="Start", command=self.start_machine)
        self.start_btn.pack(side="left", padx=10)
        self.stop_btn = ttk.Button(frame, text="Stop", command=self.stop_machine, state="disabled")
        self.stop_btn.pack(side="left")

    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Ready. Please start the machine.")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w", padding=2)
        status_bar.grid(row=2, column=0, sticky="ew")

    # --- View Management ---
    def switch_to_contact_view(self):
        if self.current_view:
            self.current_view.grid_forget()
        self.current_chat_mac = None
        self.contact_view.grid(row=1, column=0, sticky="nsew")
        self.current_view = self.contact_view
        if self.machine:
            self.contact_view.update_list(self.contacts, self.machine._MAC)

    def switch_to_chat_view(self, mac):
        if self.machine and mac == self.machine._MAC:
            messagebox.showinfo("Info", "You cannot open a chat with yourself.")
            return
        
        if self.current_view:
            self.current_view.grid_forget()
        self.current_chat_mac = mac
        self.chat_view.grid(row=1, column=0, sticky="nsew")
        self.current_view = self.chat_view
        
        self.chat_view.set_chat_target(self.contacts.get(mac, mac), mac)
        self.chat_view.load_history(self.chat_histories.get(mac, []))
        self.chat_view.attach_btn.config(state="normal")

    # --- Backend Logic ---
    def start_machine(self):
        iface = self.iface_var.get()
        if not iface or iface == "Select...":
            messagebox.showerror("Error", "Please select a valid network interface.")
            return
        try:
            ethertype = int(self.ethertype_var.get(), 16)
        except ValueError:
            messagebox.showerror("Error", "Invalid Ethertype. Must be a hex value (e.g., 0x1234).")
            return

        self.machine = Machine(interface=iface, ethertype=ethertype, frame_handler=self.on_frame_received, discovery_handler=self.on_discovery)
        self.machine.start()

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.iface_combo.config(state="disabled")
        self.ethertype_entry.config(state="disabled")
        self.status_var.set(f"Running on {iface} | MAC: {self.machine._MAC} | Ethertype: {hex(ethertype)}")
        
        self.contacts[self.machine._MAC] = "Me"
        self.contact_view.update_list(self.contacts, self.machine._MAC)

    def stop_machine(self):
        if self.machine:
            self.machine.stop()
        self.machine = None
        
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.iface_combo.config(state="readonly")
        self.ethertype_entry.config(state="normal")
        self.status_var.set("Stopped. Start the machine to connect.")
        
        self.contacts = {}
        self.chat_histories = {}
        self.contact_view.update_list(self.contacts, "")
        self.switch_to_contact_view()
        self.chat_view.attach_btn.config(state="disabled")


    def on_frame_received(self, dest_mac, src_mac, payload):
        self.message_queue.put(("message", {"src": src_mac, "payload": payload}))

    def on_discovery(self, mac):
        self.message_queue.put(("discovery", {"mac": mac}))

    def _process_queue(self):
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                if msg_type == "message":
                    self._handle_incoming_message(data["src"], data["payload"])
                elif msg_type == "discovery":
                    mac = data["mac"]
                    if mac not in self.contacts:
                        self.contacts[mac] = f"New Peer ({mac[-5:]})"
                        if self.current_view == self.contact_view:
                            self.contact_view.update_list(self.contacts, self.machine._MAC)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_queue)

    # --- UI Event Handlers / Callbacks ---
    def _rename_contact(self, mac):
        if self.machine and mac == self.machine._MAC:
            messagebox.showerror("Error", "You cannot rename yourself.")
            return

        new_name = simpledialog.askstring("Rename Contact", "Enter new name:", parent=self)
        if new_name:
            self.contacts[mac] = new_name
            self.contact_view.update_list(self.contacts, self.machine._MAC)

    def _send_message(self, msg_text):
        if not self.current_chat_mac or not self.machine: return
        
        payload = b"TXT:" + msg_text.encode()
        self.machine.send_data(self.current_chat_mac, payload)
        
        # Add to history and update view
        self._add_to_history(self.current_chat_mac, "You", msg_text, True)

    def _send_file(self):
        if not self.current_chat_mac or not self.machine: return

        filepath = filedialog.askopenfilename(title="Select a file to send")
        if not filepath:
            return

        filename = os.path.basename(filepath)
        try:
            with open(filepath, "rb") as f:
                file_content = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file: {e}")
            return

        payload = b"FILE:" + filename.encode() + b"::" + file_content
        
        self.status_var.set(f"Sending {filename} ({len(payload)} bytes)...")
        self.update_idletasks()

        def progress_update(percentage: int):
            self.chat_view.update_progress_bar(percentage)

        def on_send_complete():
            self.chat_view.hide_progress_bar()
            self.chat_view.send_btn.config(state="normal")
            self.chat_view.attach_btn.config(state="normal")
            self.status_var.set(f"File {filename} sent successfully.")
            self._add_to_history(self.current_chat_mac, "System", f"File sent: {filename}", True)

        self.chat_view.show_progress_bar(f"Sending {filename}...")
        self.chat_view.send_btn.config(state="disabled")
        self.chat_view.attach_btn.config(state="disabled")

        self.machine.send_data(
            self.current_chat_mac, 
            payload,
            progress_callback=lambda pct: self.after(0, progress_update, pct),
            completion_callback=lambda: self.after(0, on_send_complete)
        )

    def _handle_incoming_message(self, src_mac, payload: bytes):
        if payload.startswith(b"BROADCAST:"):
            text = payload[10:].decode(errors="ignore")
            sender_name = self.contacts.get(src_mac, src_mac)
            self.contact_view.add_broadcast_message(sender_name, text)
        elif payload.startswith(b"TXT:"):
            text = payload[4:].decode(errors="ignore")
            sender_name = self.contacts.get(src_mac, src_mac)
            self._add_to_history(src_mac, sender_name, text, False)
            if src_mac != self.current_chat_mac:
                self.status_var.set(f"New message from {sender_name}")

        elif payload.startswith(b"FILE:"):
            header, file_content = payload[5:].split(b"::", 1)
            filename = header.decode(errors="ignore")
            sender_name = self.contacts.get(src_mac, src_mac)
            
            self.status_var.set(f"Incoming file '{filename}' from {sender_name}.")
            self._add_to_history(src_mac, "System", f"File received: '{filename}'.", False)
            
            self.after(100, lambda: self._prompt_save_file(filename, file_content))

    def _prompt_save_file(self, filename, content):
        if messagebox.askyesno("Incoming File", f"You have received a file: '{filename}'.\nDo you want to save it?"):
            save_path = filedialog.asksaveasfilename(initialfile=filename, title="Save file as...")
            if save_path:
                try:
                    with open(save_path, "wb") as f:
                        f.write(content)
                    messagebox.showinfo("Success", f"File saved successfully to:\n{save_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not save file: {e}")

    def _add_to_history(self, mac_key, sender_display, text, is_self):
        """Helper function to manage chat history and update the view."""
        message = {"sender_display": sender_display, "text": text, "is_self": is_self}
        if mac_key not in self.chat_histories:
            self.chat_histories[mac_key] = []
        self.chat_histories[mac_key].append(message)

        if mac_key == self.current_chat_mac:
            self.chat_view.add_message(message["sender_display"], message["text"], message["is_self"])


    def _on_closing(self):
        if self.machine and self.machine._running:
            if messagebox.askokcancel("Quit", "The machine is still running. Do you want to stop it and quit?"):
                self.stop_machine()
                self.machine._socket.close() # Final close
                self.destroy()
        else:
            if self.machine: self.machine._socket.close()
            self.destroy()