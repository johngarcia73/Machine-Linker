import tkinter as tk
from tkinter import ttk

class ChatView(ttk.Frame):
    def __init__(self, parent, send_callback, back_callback, attach_callback):
        super().__init__(parent, padding=10)
        self.send_callback = send_callback
        self.attach_callback = attach_callback
        
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # --- Header ---
        header_frame = ttk.Frame(self)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        back_btn = ttk.Button(header_frame, text="< Back", command=back_callback)
        back_btn.pack(side="left")

        
        
        self.chat_title_var = tk.StringVar()
        ttk.Label(header_frame, textvariable=self.chat_title_var, font=("Helvetica", 14, "bold")).pack(side="left", padx=20)

        # --- Chat History ---
        history_container = ttk.Frame(self)
        history_container.grid(row=1, column=0, sticky="nsew")
        history_container.grid_rowconfigure(0, weight=1)
        history_container.grid_columnconfigure(0, weight=1)

        self.chat_history = tk.Text(history_container, state="disabled", wrap="word", font=("Helvetica", 11))
        self.chat_history.grid(row=0, column=0, sticky="nsew")
        
        scroll = ttk.Scrollbar(history_container, orient="vertical", command=self.chat_history.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.chat_history.config(yscrollcommand=scroll.set)

        # --- Message Input ---
        input_frame = ttk.Frame(self, padding=(0, 10, 0, 0))
        input_frame.grid(row=2, column=0, sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)

        self.msg_var = tk.StringVar()
        self.msg_entry = ttk.Entry(input_frame, textvariable=self.msg_var, font=("Helvetica", 11))
        self.msg_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.msg_entry.bind("<Return>", self._on_send)

        self.send_btn = ttk.Button(input_frame, text="Send", command=self._on_send)
        self.send_btn.grid(row=0, column=1, padx=(0, 5))

        self.attach_btn = ttk.Button(input_frame, text="📎", command=self.attach_callback, width=3)
        self.attach_btn.grid(row=0, column=2)

        self.progress_frame = ttk.Frame(self)
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.pack(side="left", padx=(0, 5))
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side="left", fill="x", expand=True)
        self.percent_label = ttk.Label(self.progress_frame, text="0%")
        self.percent_label.pack(side="left", padx=5)

    def set_chat_target(self, name, mac):
        self.chat_title_var.set(f"{name} ({mac})")
        self.msg_entry.focus()

    def add_message(self, sender_display, text, is_self):
        self.chat_history.config(state="normal")
        
        self.chat_history.tag_configure("self", justify='right', foreground='#004D40', background='#E0F2F1')
        self.chat_history.tag_configure("other", justify='left', foreground='#000000', background='#FFFFFF')
        self.chat_history.tag_configure("system", justify='center', foreground='grey', font=("Helvetica", 9, "italic"))

        tag = "self" if is_self else "other"
        
        # Use system tag for file notifications
        if "File sent:" in text or "File received:" in text:
            tag = "system"

        self.chat_history.insert(tk.END, f"{sender_display}: {text}\n", tag)
        
        self.chat_history.config(state="disabled")
        self.chat_history.see(tk.END) # Auto-scroll to the bottom

    def load_history(self, messages):
        self.chat_history.config(state="normal")
        self.chat_history.delete(1.0, tk.END)
        self.chat_history.config(state="disabled")
        for msg in messages:
            self.add_message(msg["sender_display"], msg["text"], msg["is_self"])

    def _on_send(self, event=None):
        msg = self.msg_var.get()
        if msg:
            self.send_callback(msg)
            self.msg_var.set("")

    def show_progress_bar(self, text=""):
        """Muestra la barra de progreso."""
        self.progress_label.config(text=text)
        self.progress_var.set(0)
        self.percent_label.config(text="0%")
        self.progress_frame.grid(row=3, column=0, sticky="ew", pady=(5, 0))

    def update_progress_bar(self, pct):
        """Actualiza el valor de la barra de progreso."""
        self.progress_var.set(pct)
        self.percent_label.config(text=f"{pct}%")

    def hide_progress_bar(self):
        """Oculta la barra de progreso."""
        self.progress_frame.grid_remove()