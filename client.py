import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
from datetime import datetime
from Crypto.Random import get_random_bytes
import base64

from encryption import derive_key, encrypt, decrypt, SALT  # Import custom encryption logic

class ChatApp:
    def __init__(self, is_server):
        # Prompt for password and username
        self.password = simpledialog.askstring("Password", "Enter shared password:", show='*')
        self.username = simpledialog.askstring("Username", "Enter your username:")
        self.salt = SALT  # Initial salt (can be replaced later)
        self.key = derive_key(self.password)
        self.message_count = 0

        # GUI setup
        self.window = tk.Tk()
        self.window.title("Messenger")

        self.text_frame = tk.Frame(self.window)
        self.text_frame.pack(fill=tk.BOTH, expand=True)

        self.plain_area = scrolledtext.ScrolledText(self.text_frame, width=50)
        self.plain_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.plain_area.insert(tk.END, "[Plaintext]\n")

        self.cipher_area = scrolledtext.ScrolledText(self.text_frame, width=50)
        self.cipher_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.cipher_area.insert(tk.END, "[Ciphertext]\n")

        self.entry_frame = tk.Frame(self.window)
        self.entry_frame.pack(fill=tk.BOTH, expand=True)

        self.entry = tk.Entry(self.entry_frame)
        self.entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self.entry_frame, text="Send", command=lambda: self.send_message(None))
        self.send_button.pack(side=tk.RIGHT)

        # Connect to server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip = simpledialog.askstring("Server IP", "Enter the server's IP address:")
        if not ip:
            print("[ERROR] No IP entered.")
            return
        print(f"[CLIENT] Connecting to {ip}...")
        self.sock.connect((ip, 12345))
        self.conn = self.sock

        # Exchange usernames
        self.conn.sendall(self.username.encode() + b'\n')
        peer_name = b''
        while not peer_name.endswith(b'\n'):
            peer_name += self.conn.recv(1)
        self.peer_username = peer_name.decode().strip()

        # Start receiving messages
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.window.mainloop()

    def send_message(self, event):
        msg = self.entry.get()
        if not msg:
            return
        self.entry.delete(0, tk.END)

        self.message_count += 1

        # Rotate key every 10 messages
        if self.message_count % 10 == 0:
            new_salt = get_random_bytes(16)
            self.salt = new_salt
            self.key = derive_key(self.password)
            print(f"[DEBUG] New derived key: {self.key.hex()}")
            encoded_salt = base64.b64encode(new_salt).decode()
            self.conn.sendall(f"__SALT__:{encoded_salt}\n".encode())
            self.cipher_area.insert(tk.END, "[SYSTEM] Sent new salt to peer\n")

        # Encrypt and send message
        enc = encrypt(self.key, msg)
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.plain_area.insert(tk.END, f"[{timestamp}] {self.username}: {msg}\n")
        self.cipher_area.insert(tk.END, f"[{timestamp}] {self.username}: {enc}\n")
        self.conn.sendall(enc.encode() + b'\n')

    def receive_messages(self):
        buffer = b""
        while True:
            try:
                data = self.conn.recv(1024)
                if not data:
                    break
                buffer += data

                while b"\n" in buffer:
                    msg, buffer = buffer.split(b"\n", 1)
                    incoming = msg.decode()

                    if incoming.startswith("__SALT__:"):
                        new_salt = base64.b64decode(incoming.split(":", 1)[1])
                        self.salt = new_salt
                        self.key = derive_key(self.password)
                        print(f"[DEBUG] New derived key: {self.key.hex()}")
                        self.plain_area.insert(tk.END, "[SYSTEM] Received new salt, key updated\n")
                        continue

                    # Decrypt normal message
                    decoded = decrypt(self.key, incoming)
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    self.plain_area.insert(tk.END, f"[{timestamp}] {self.peer_username}: {decoded}\n")
                    self.cipher_area.insert(tk.END, f"[{timestamp}] {self.peer_username}: {incoming}\n")
            except Exception as e:
                self.plain_area.insert(tk.END, f"Error: {e}\n")
                break

if __name__ == '__main__':
    ChatApp(is_server=False)
