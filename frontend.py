import tkinter as tk
from tkinter import ttk, messagebox
import threading
from connections import Machine
import os

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ethernet P2P Frontend")
        self.geometry("700x450")
        self.resizable(False, False)

        # --- Variables internas ---
        self.machine: Machine | None = None
        self.running = False

        # --- UI ---
        self._build_controls()
        self._build_discovery_panel()
        self._build_message_panel()

    # ---------- UI Sections ----------
    def _build_controls(self):
        frame = ttk.LabelFrame(self, text="Configuración")
        frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame, text="Interfaz:").grid(row=0, column=0, padx=5, pady=5)
        interfaces = Machine.list_interfaces()
        self.iface_var = tk.StringVar(value=interfaces[0] if interfaces else "")
        self.iface_combo = ttk.Combobox(frame, textvariable=self.iface_var, values=interfaces, state="readonly")
        self.iface_combo.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Ethertype (hex):").grid(row=0, column=2, padx=5, pady=5)
        self.ethertype_var = tk.StringVar(value="0x1234")
        ttk.Entry(frame, textvariable=self.ethertype_var, width=10).grid(row=0, column=3, padx=5, pady=5)

        self.start_btn = ttk.Button(frame, text="Iniciar", command=self.start_machine)
        self.start_btn.grid(row=0, column=4, padx=10)

        self.stop_btn = ttk.Button(frame, text="Detener", command=self.stop_machine, state="disabled")
        self.stop_btn.grid(row=0, column=5, padx=10)

    def _build_discovery_panel(self):
        frame = ttk.LabelFrame(self, text="Máquinas descubiertas")
        frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.machines_list = tk.Listbox(frame, height=8)
        self.machines_list.pack(fill="both", expand=True, padx=5, pady=5)

    def _build_message_panel(self):
        frame = ttk.LabelFrame(self, text="Enviar mensaje")
        frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame, text="Destino (MAC):").grid(row=0, column=0, padx=5, pady=5)
        self.dest_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.dest_var, width=20).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Mensaje:").grid(row=0, column=2, padx=5, pady=5)
        self.msg_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.msg_var, width=30).grid(row=0, column=3, padx=5, pady=5)

        ttk.Button(frame, text="Enviar", command=self.send_message).grid(row=0, column=4, padx=5, pady=5)

        # Panel de log
        self.log = tk.Text(self, height=8, state="disabled")
        self.log.pack(fill="both", expand=True, padx=10, pady=5)

    # ---------- Machine control ----------
    def start_machine(self):
        if not self.iface_var.get():
            messagebox.showerror("Error", "Seleccione una interfaz.")
            return

        try:
            ethertype = int(self.ethertype_var.get(), 16)
        except ValueError:
            messagebox.showerror("Error", "Ethertype inválido.")
            return

        # Crear la máquina
        self.machine = Machine(
            interface=self.iface_var.get(),
            ethertype=ethertype,
            frame_handler=self.on_frame
        )
        self.machine.start()
        self.running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        self.log_message(f"Escuchando en {self.iface_var.get()} (ethertype {hex(ethertype)})")
        self.refresh_discovered()

        # Actualización periódica
        self.after(2000, self.refresh_discovered)

    def stop_machine(self):
        if self.machine:
            self.machine.stop()
            self.machine = None
        self.running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log_message("Captura detenida.")

    # ---------- Actions ----------
    def refresh_discovered(self):
        if not self.running or not self.machine:
            return
        self.machines_list.delete(0, tk.END)
        for mac, name in self.machine._discovered_machines.items():
            self.machines_list.insert(tk.END, f"{mac}   ({name})")
        # Repetir actualización
        self.after(2000, self.refresh_discovered)

    def send_message(self):
        if not self.machine:
            messagebox.showerror("Error", "La máquina no está en ejecución.")
            return
        dest = self.dest_var.get().strip()
        data = self.msg_var.get().encode()
        if not dest or not data:
            messagebox.showerror("Error", "MAC destino y mensaje son obligatorios.")
            return
        self.machine.send_data(dest, data)
        self.log_message(f"Enviado a {dest}: {self.msg_var.get()}")
        self.msg_var.set("")

    def on_frame(self, dest, src, payload):
        # Callback desde Machine para cada mensaje P2P
        text = payload.decode(errors="ignore")
        self.log_message(f"[{src}] -> [{dest}]: {text}")

    def log_message(self, msg):
        self.log.configure(state="normal")
        self.log.insert(tk.END, msg + "\n")
        self.log.configure(state="disabled")
        self.log.see(tk.END)

if __name__ == "__main__":
    app = App()
    app.mainloop()
