## How to Run

### 1. Start the Server

On one machine (or terminal tab), run:

```bash
python server.py
```

You will be prompted for:

* Shared password
* Username

The application will wait for a client to connect.

---

### 2. Start the Client

On the second machine, run:

```bash
python client.py
```

You will be prompted for:

* Shared password (must match the server's password)
* Username
* Server's IP address

Depending on your setup, here’s what to enter:

#### 🔹 If running on the same machine (for local testing):

Enter:

```bash
127.0.0.1
```

#### 🔹 If running on different machines on the **same Wi-Fi network**:

* On the server machine, run:

  ```bash
  ipconfig     # Windows
  ifconfig     # macOS/Linux
  ```
* Find your **local IP** (e.g., `192.168.0.105`)
* Enter that IP on the client when prompted

#### If running on **different networks (e.g., home and mobile)**:

1. On the server machine:

   * Visit [https://whatismyipaddress.com](https://whatismyipaddress.com) to find your **public IP**
   * Log into your **router settings** and **forward port 12345** to your local IP address

     * Look for "Port Forwarding" or "Virtual Server"
     * Forward port 12345 (TCP) to the computer running the server
2. On the client machine:

   * Enter the **public IP** of the server machine when prompted

**Note:** Port forwarding must be configured for external connections to succeed.

---

## Project Structure

```bash
.
├── client.py         # Launches the client GUI
├── server.py         # Launches the server GUI
├── encryption.py     # Contains encryption logic
├── README.md         # Project documentation
```
