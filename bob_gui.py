"""
Bob GUI - TCP Client Side
Generates RSA keys, connects to Alice, and communicates securely
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import pickle
import rsa_manual
from queue import Queue
import time


class BobGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Bob - RSA Client")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Network settings
        self.HOST = "127.0.0.1"
        self.PORT = 3000
        self.socket = None
        self.connected = False
        
        # Keys
        self.bob_public = None
        self.bob_private = None
        self.alice_public = None
        self.alice_private = None
        
        # Message queue
        self.message_queue = Queue()
        self.received_messages = []
        
        # Colors
        self.bg_color = "#1e1e2e"
        self.bg_light = "#2a2a3e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#f9e2af"
        self.success_color = "#a6e3a1"
        self.error_color = "#f38ba8"
        self.warning_color = "#fab387"
        
        self.root.configure(bg=self.bg_color)
        self.setup_ui()
    
    def setup_ui(self):
        # Header
        header = tk.Frame(self.root, bg=self.bg_color, height=60)
        header.pack(fill=tk.X, padx=10, pady=10)
        header.pack_propagate(False)
        
        tk.Label(
            header,
            text="👨 Bob - RSA TCP Client",
            font=("Segoe UI", 20, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        ).pack()
        
        # Connection settings frame
        conn_frame = tk.Frame(header, bg=self.bg_color)
        conn_frame.pack()
        
        tk.Label(
            conn_frame,
            text="Server:",
            font=("Segoe UI", 9),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(side=tk.LEFT)
        
        self.host_entry = tk.Entry(
            conn_frame,
            width=15,
            font=("Segoe UI", 9),
            bg=self.bg_light,
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.host_entry.insert(0, self.HOST)
        self.host_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(
            conn_frame,
            text="Port:",
            font=("Segoe UI", 9),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        self.port_entry = tk.Entry(
            conn_frame,
            width=8,
            font=("Segoe UI", 9),
            bg=self.bg_light,
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.port_entry.insert(0, str(self.PORT))
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        # Status bar at top
        self.status_label = tk.Label(
            self.root,
            text="⚪ Not connected - Generate keys and connect to Alice",
            font=("Segoe UI", 9),
            bg=self.bg_light,
            fg=self.fg_color,
            anchor=tk.W,
            padx=10,
            pady=5
        )
        self.status_label.pack(fill=tk.X, padx=10)
        
        # Main content area
        content = tk.Frame(self.root, bg=self.bg_color)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left panel - Controls
        left_panel = tk.Frame(content, bg=self.bg_light, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        left_panel.pack_propagate(False)
        
        self.create_control_panel(left_panel)
        
        # Right panel - Messages
        right_panel = tk.Frame(content, bg=self.bg_color)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.create_message_panel(right_panel)
    
    def create_control_panel(self, parent):
        # Key Generation Section
        tk.Label(
            parent,
            text="🔑 Key Management",
            font=("Segoe UI", 12, "bold"),
            bg=self.bg_light,
            fg=self.accent_color
        ).pack(pady=(10, 5), padx=10, anchor=tk.W)
        
        self.gen_btn = tk.Button(
            parent,
            text="🚀 Generate Keys",
            command=self.generate_keys,
            bg=self.accent_color,
            fg=self.bg_color,
            font=("Segoe UI", 10, "bold"),
            padx=15,
            pady=8,
            cursor="hand2",
            border=0
        )
        self.gen_btn.pack(pady=5, padx=10, fill=tk.X)
        
        self.key_status = tk.Label(
            parent,
            text="❌ No keys",
            font=("Segoe UI", 9),
            bg=self.bg_light,
            fg=self.error_color
        )
        self.key_status.pack(pady=2, padx=10)
        
        # Bob's Public Key Display
        tk.Label(
            parent,
            text="📤 Bob's Public Key (Your Key)",
            font=("Segoe UI", 9, "bold"),
            bg=self.bg_light,
            fg=self.accent_color
        ).pack(pady=(5, 2), padx=10, anchor=tk.W)
        
        self.bob_pub_display = tk.Text(
            parent,
            height=3,
            font=("Consolas", 8),
            bg="#0d1117",
            fg=self.accent_color,
            wrap=tk.WORD,
            padx=5,
            pady=5
        )
        self.bob_pub_display.pack(pady=2, padx=10, fill=tk.X)
        self.bob_pub_display.insert(1.0, "Generate keys first...")
        self.bob_pub_display.config(state=tk.DISABLED)
        
        # Bob's Private Key Display
        tk.Label(
            parent,
            text="🔒 Bob's Private Key (Your Key - Keep Secret!)",
            font=("Segoe UI", 9, "bold"),
            bg=self.bg_light,
            fg=self.error_color
        ).pack(pady=(5, 2), padx=10, anchor=tk.W)
        
        self.bob_priv_display = tk.Text(
            parent,
            height=3,
            font=("Consolas", 8),
            bg="#0d1117",
            fg=self.error_color,
            wrap=tk.WORD,
            padx=5,
            pady=5
        )
        self.bob_priv_display.pack(pady=2, padx=10, fill=tk.X)
        self.bob_priv_display.insert(1.0, "Generate keys first...")
        self.bob_priv_display.config(state=tk.DISABLED)
        
        # Connection Control
        tk.Label(
            parent,
            text="🌐 Connection",
            font=("Segoe UI", 12, "bold"),
            bg=self.bg_light,
            fg=self.accent_color
        ).pack(pady=(15, 5), padx=10, anchor=tk.W)
        
        self.connect_btn = tk.Button(
            parent,
            text="🔌 Connect to Alice",
            command=self.toggle_connection,
            bg=self.success_color,
            fg=self.bg_color,
            font=("Segoe UI", 10, "bold"),
            padx=15,
            pady=8,
            cursor="hand2",
            border=0,
            state=tk.DISABLED
        )
        self.connect_btn.pack(pady=5, padx=10, fill=tk.X)
        
        self.connection_status = tk.Label(
            parent,
            text="⚪ Not connected",
            font=("Segoe UI", 9),
            bg=self.bg_light,
            fg=self.fg_color
        )
        self.connection_status.pack(pady=2, padx=10)
        
        # Alice's Public Key
        tk.Label(
            parent,
            text="📥 Alice's Public Key (Received)",
            font=("Segoe UI", 9, "bold"),
            bg=self.bg_light,
            fg=self.warning_color
        ).pack(pady=(15, 2), padx=10, anchor=tk.W)
        
        self.alice_pub_display = tk.Text(
            parent,
            height=3,
            font=("Consolas", 8),
            bg="#0d1117",
            fg=self.warning_color,
            wrap=tk.WORD,
            padx=5,
            pady=5
        )
        self.alice_pub_display.pack(pady=2, padx=10, fill=tk.X)
        self.alice_pub_display.insert(1.0, "Not connected to Alice yet...")
        self.alice_pub_display.config(state=tk.DISABLED)
        
        # Alice's Private Key
        tk.Label(
            parent,
            text="🔐 Alice's Private Key (Received)",
            font=("Segoe UI", 9, "bold"),
            bg=self.bg_light,
            fg=self.error_color
        ).pack(pady=(5, 2), padx=10, anchor=tk.W)
        
        self.alice_priv_display = tk.Text(
            parent,
            height=3,
            font=("Consolas", 8),
            bg="#0d1117",
            fg=self.error_color,
            wrap=tk.WORD,
            padx=5,
            pady=5
        )
        self.alice_priv_display.pack(pady=2, padx=10, fill=tk.X)
        self.alice_priv_display.insert(1.0, "Not connected to Alice yet...")
        self.alice_priv_display.config(state=tk.DISABLED)
    
    def create_message_panel(self, parent):
        # Send Section
        send_frame = tk.Frame(parent, bg=self.bg_light)
        send_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        tk.Label(
            send_frame,
            text="📤 Send Message to Alice",
            font=("Segoe UI", 12, "bold"),
            bg=self.bg_light,
            fg=self.accent_color
        ).pack(pady=10, padx=10, anchor=tk.W)
        
        self.send_input = scrolledtext.ScrolledText(
            send_frame,
            height=6,
            font=("Segoe UI", 11),
            bg="white",
            fg="#1e1e1e",
            padx=10,
            pady=10,
            wrap=tk.WORD
        )
        self.send_input.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Encryption toggle
        encrypt_toggle_frame = tk.Frame(send_frame, bg=self.bg_light)
        encrypt_toggle_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        self.encrypt_var = tk.BooleanVar(value=True)
        self.encrypt_check = tk.Checkbutton(
            encrypt_toggle_frame,
            text="🔒 Encrypt message (RSA)",
            variable=self.encrypt_var,
            command=self.toggle_encryption,
            bg=self.bg_light,
            fg=self.fg_color,
            selectcolor=self.bg_color,
            font=("Segoe UI", 9, "bold"),
            activebackground=self.bg_light,
            activeforeground=self.accent_color
        )
        self.encrypt_check.pack(side=tk.LEFT, padx=5)
        
        send_btn_frame = tk.Frame(send_frame, bg=self.bg_light)
        send_btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.send_btn = tk.Button(
            send_btn_frame,
            text="🔒 Encrypt & Send",
            command=self.send_message,
            bg=self.accent_color,
            fg=self.bg_color,
            font=("Segoe UI", 11, "bold"),
            padx=20,
            pady=8,
            cursor="hand2",
            border=0,
            state=tk.DISABLED
        )
        self.send_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            send_btn_frame,
            text="Clear",
            command=lambda: self.send_input.delete(1.0, tk.END),
            bg=self.bg_light,
            fg=self.fg_color,
            font=("Segoe UI", 9),
            padx=15,
            pady=8,
            cursor="hand2",
            border=0
        ).pack(side=tk.LEFT, padx=5)
        
        # Receive Section
        receive_frame = tk.Frame(parent, bg=self.bg_light)
        receive_frame.pack(fill=tk.BOTH, expand=True)
        
        recv_header = tk.Frame(receive_frame, bg=self.bg_light)
        recv_header.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            recv_header,
            text="📥 Received from Alice",
            font=("Segoe UI", 12, "bold"),
            bg=self.bg_light,
            fg=self.success_color
        ).pack(side=tk.LEFT)
        
        self.refresh_btn = tk.Button(
            recv_header,
            text="🔄 Refresh",
            command=self.refresh_messages,
            bg=self.success_color,
            fg=self.bg_color,
            font=("Segoe UI", 9, "bold"),
            padx=15,
            pady=5,
            cursor="hand2",
            border=0
        )
        self.refresh_btn.pack(side=tk.RIGHT)
        
        self.receive_output = scrolledtext.ScrolledText(
            receive_frame,
            height=10,
            font=("Segoe UI", 10),
            bg="#0d1117",
            fg=self.fg_color,
            padx=10,
            pady=10,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.receive_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
    
    def generate_keys(self):
        """Generate Bob's RSA keys"""
        self.gen_btn.config(state=tk.DISABLED, text="⏳ Generating...")
        self.key_status.config(text="⏳ Generating...", fg=self.warning_color)
        
        def generate():
            try:
                self.bob_public, self.bob_private = rsa_manual.generate_keypair(bit_length=512)
                self.root.after(0, self.on_keys_generated)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Key generation failed: {e}"))
                self.root.after(0, lambda: self.gen_btn.config(state=tk.NORMAL, text="🚀 Generate Keys"))
        
        threading.Thread(target=generate, daemon=True).start()
    
    def on_keys_generated(self):
        """Called when keys are generated"""
        # Display Bob's public key
        self.bob_pub_display.config(state=tk.NORMAL)
        self.bob_pub_display.delete(1.0, tk.END)
        e, n = self.bob_public
        self.bob_pub_display.insert(1.0, f"e = {e}\nn = {n}\nn bit_length = {n.bit_length()} bits")
        self.bob_pub_display.config(state=tk.DISABLED)
        
        # Display Bob's private key
        self.bob_priv_display.config(state=tk.NORMAL)
        self.bob_priv_display.delete(1.0, tk.END)
        d, n = self.bob_private
        self.bob_priv_display.insert(1.0, f"d = {d}\nn = {n}\nd bit_length = {d.bit_length()} bits")
        self.bob_priv_display.config(state=tk.DISABLED)
        
        self.gen_btn.config(state=tk.NORMAL, text="✅ Keys Generated")
        self.key_status.config(text=f"✅ 1024-bit keys ready", fg=self.success_color)
        self.connect_btn.config(state=tk.NORMAL)
        self.status_label.config(text="✅ Keys ready - Connect to Alice's server", fg=self.success_color)
        messagebox.showinfo("Success", "🎉 RSA keys generated!\n\nYou can now connect to Alice.")
    
    def toggle_connection(self):
        """Connect/disconnect from Alice"""
        if not self.connected:
            self.connect_to_alice()
        else:
            self.disconnect()
    
    def connect_to_alice(self):
        """Connect to Alice's server"""
        host = self.host_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number!")
            return
        
        self.connect_btn.config(state=tk.DISABLED, text="⏳ Connecting...")
        self.connection_status.config(text="⏳ Connecting...", fg=self.warning_color)
        
        def connect():
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((host, port))
                
                # Send Bob's public key only
                bob_pub_data = pickle.dumps(self.bob_public)
                self.socket.send(bob_pub_data)
                
                # Receive Alice's public key only
                alice_pub_data = self.socket.recv(4096)
                self.alice_public = pickle.loads(alice_pub_data)
                
                self.connected = True
                self.root.after(0, self.on_connected)
                
                # Listen for messages
                self.listen_for_messages()
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Connection Failed", f"Could not connect to Alice:\n{e}"))
                self.root.after(0, lambda: self.connect_btn.config(state=tk.NORMAL, text="🔌 Connect to Alice"))
                self.root.after(0, lambda: self.connection_status.config(text="❌ Connection failed", fg=self.error_color))
        
        threading.Thread(target=connect, daemon=True).start()
    
    def on_connected(self):
        """Called when connected to Alice"""
        self.connect_btn.config(state=tk.NORMAL, text="🔌 Disconnect", bg=self.error_color)
        self.connection_status.config(text="🟢 Connected to Alice", fg=self.success_color)
        self.status_label.config(text="✅ Connected - Keys exchanged. You can send/receive messages", fg=self.success_color)
        
        # Display Alice's public key
        self.alice_pub_display.config(state=tk.NORMAL)
        self.alice_pub_display.delete(1.0, tk.END)
        e, n = self.alice_public
        self.alice_pub_display.insert(1.0, f"e = {e}\nn = {n}\nn bit_length = {n.bit_length()} bits")
        self.alice_pub_display.config(state=tk.DISABLED)
        
        # Alice's private key is NOT exchanged (secure)
        self.alice_priv_display.config(state=tk.NORMAL)
        self.alice_priv_display.delete(1.0, tk.END)
        self.alice_priv_display.insert(1.0, "🔒 Not exchanged\n\nAlice's private key stays with Alice for security.")
        self.alice_priv_display.config(state=tk.DISABLED)
        
        self.send_btn.config(state=tk.NORMAL)
        self.host_entry.config(state=tk.DISABLED)
        self.port_entry.config(state=tk.DISABLED)
        
        messagebox.showinfo("Connected", "✅ Connected to Alice!\n\nKeys exchanged. You can now send encrypted messages.")
    
    def disconnect(self):
        """Disconnect from Alice"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.connect_btn.config(text="🔌 Connect to Alice", bg=self.success_color)
        self.connection_status.config(text="⚪ Not connected", fg=self.fg_color)
        self.status_label.config(text="⚪ Disconnected from Alice", fg=self.fg_color)
        self.send_btn.config(state=tk.DISABLED)
        self.host_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
    
    def listen_for_messages(self):
        """Listen for incoming messages from Alice"""
        def listen():
            try:
                while self.connected and self.socket:
                    data = self.socket.recv(4096)
                    if not data:
                        break
                    
                    ciphertext = pickle.loads(data)
                    self.message_queue.put(ciphertext)
                    
            except Exception as e:
                if self.connected:
                    self.root.after(0, lambda: self.status_label.config(
                        text=f"⚠️ Connection lost: {e}", fg=self.error_color))
                    self.root.after(0, self.disconnect)
        
        threading.Thread(target=listen, daemon=True).start()
    
    def toggle_encryption(self):
        """Update button text when encryption toggle changes"""
        if self.encrypt_var.get():
            self.send_btn.config(text="🔒 Encrypt & Send")
        else:
            self.send_btn.config(text="📤 Send (Unencrypted)")
    
    def send_message(self):
        """Send message to Alice (encrypted or unencrypted)"""
        plaintext = self.send_input.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showerror("Error", "Please enter a message!")
            return
        
        try:
            if self.encrypt_var.get():
                # Encrypted mode
                if not self.alice_public:
                    messagebox.showerror("Error", "Alice's public key not received yet!")
                    return
                
                # Encrypt with Alice's public key
                ciphertext = rsa_manual.encrypt_string(plaintext, self.alice_public)
                data = pickle.dumps({"encrypted": True, "content": ciphertext})
                self.socket.send(data)
                
                self.send_input.delete(1.0, tk.END)
                self.status_label.config(text=f"✅ Message sent to Alice (encrypted)", fg=self.success_color)
                messagebox.showinfo("Sent", "🔒 Message encrypted and sent to Alice!")
            else:
                # Unencrypted mode
                data = pickle.dumps({"encrypted": False, "content": plaintext})
                self.socket.send(data)
                
                self.send_input.delete(1.0, tk.END)
                self.status_label.config(text=f"⚠️ Message sent to Alice (UNENCRYPTED)", fg=self.warning_color)
                messagebox.showwarning("Sent", "⚠️ Message sent UNENCRYPTED to Alice!\n\nAnyone can read this message.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send: {e}")
    
    def refresh_messages(self):
        """Check for new messages and decrypt them"""
        if self.message_queue.empty():
            self.status_label.config(text="ℹ️ No new messages", fg=self.fg_color)
            return
        
        # Process all queued messages
        new_messages = []
        while not self.message_queue.empty():
            message_data = self.message_queue.get()
            try:
                if message_data.get("encrypted", True):
                    # Decrypt encrypted message
                    ciphertext = message_data["content"]
                    plaintext = rsa_manual.decrypt_to_string(ciphertext, self.bob_private)
                    new_messages.append((plaintext, True))
                else:
                    # Display unencrypted message
                    plaintext = message_data["content"]
                    new_messages.append((plaintext, False))
            except Exception as e:
                new_messages.append((f"[Decryption error: {e}]", True))
        
        # Display messages
        self.receive_output.config(state=tk.NORMAL)
        for msg, was_encrypted in new_messages:
            if was_encrypted:
                self.receive_output.insert(tk.END, f"📨 Alice (🔒 encrypted): {msg}\n\n", "encrypted")
            else:
                self.receive_output.insert(tk.END, f"📨 Alice (⚠️ UNENCRYPTED): {msg}\n\n", "unencrypted")
            self.received_messages.append(msg)
        
        self.receive_output.tag_config("encrypted", foreground=self.success_color)
        self.receive_output.tag_config("unencrypted", foreground=self.warning_color)
        self.receive_output.see(tk.END)
        self.receive_output.config(state=tk.DISABLED)
        
        encrypted_count = sum(1 for _, enc in new_messages if enc)
        if encrypted_count == len(new_messages):
            self.status_label.config(text=f"✅ {len(new_messages)} new message(s) decrypted", fg=self.success_color)
            messagebox.showinfo("New Messages", f"🔓 Decrypted {len(new_messages)} message(s) from Alice!")
        else:
            self.status_label.config(text=f"✅ {len(new_messages)} new message(s) ({encrypted_count} encrypted, {len(new_messages)-encrypted_count} unencrypted)", fg=self.success_color)
            messagebox.showinfo("New Messages", f"Received {len(new_messages)} message(s):\n🔓 {encrypted_count} encrypted\n⚠️ {len(new_messages)-encrypted_count} unencrypted")


def main():
    root = tk.Tk()
    app = BobGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
