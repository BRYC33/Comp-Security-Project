## How to Run

### 1. Start the Server
On one machine (or terminal tab), run:
```bash
python server.py
```
You will be prompted for:
- Shared password
- Username

The application will wait for a client to connect.

---

### 2. Start the Client
On the second machine (same LAN or local host), run:
```bash
python client.py
```
You will be prompted for:
- Shared password (must match the server's password)
- Username
- Server's IP address (e.g., `192.168.1.10` or `127.0.0.1`)

---

## Project Structure

```bash
.
├── client.py         # Launches the client GUI
├── server.py         # Launches the server GUI
├── encryption.py     # Contains encryption logic
├── README.md         # Project documentation
