import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
from datetime import datetime
from encryption import derive_key, encrypt, decrypt

class ChatApp:
    def __init__(self, is_server):
        self.password = simpledialog.askstring("Password", "Enter shared password:", show='*')
        self.username = simpledialog.askstring("Username", "Enter your username:")
        self.key = derive_key(self.password)

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

        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.window.mainloop()

    def send_message(self, event):
        msg = self.entry.get()
        if not msg:
            return
        self.entry.delete(0, tk.END)
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
                    decoded = decrypt(self.key, msg.decode())
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    self.plain_area.insert(tk.END, f"[{timestamp}] {self.peer_username}: {decoded}\n")
                    self.cipher_area.insert(tk.END, f"[{timestamp}] {self.peer_username}: {msg.decode()}\n")
            except Exception as e:
                self.plain_area.insert(tk.END, f"Error: {e}\n")
                break

if __name__ == '__main__':
    ChatApp(is_server=False)
