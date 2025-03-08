import socket 
import threading 
from Cryptodome.Random import get_random_bytes

HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

def send_message(conn, msg):
    """Send a formatted message to the client"""
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    conn.send(send_length)
    conn.send(message)

def receive_message(conn):
    """Receive a message from the client"""
    msg_length = conn.recv(HEADER).decode(FORMAT)
    if msg_length:
        msg_length = int(msg_length.strip())  # Strip whitespace before converting
        msg = conn.recv(msg_length).decode(FORMAT)
        return msg
    return None

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    send_message(conn, "PROMPT: Select the cipher (1 for Salsa20, 2 for ChaCha20):")

    while connected:
        try:
            msg = receive_message(conn)
            if msg:
                if msg.startswith("CIPHER:"):
                    selected_cipher = msg[7:]
                    print(f"[{addr}] Selected cipher: {selected_cipher}")
                    if selected_cipher == "Salsa20":
                        send_message(conn, "PROMPT: Select the key size in bits (1 for 128, 2 for 256):")
                        size = receive_message(conn)
                        size= int(size)
                        print(type(size))
                        print(size==1)
                        if size == 1:
                            key = get_random_bytes(16)
                        elif size == 2:
                            key = get_random_bytes(32)
                        if key:
                            conn.send(key)  # Send the key as binary data
                            print(f"[{addr}] Sent key: {key.hex()}")
                    elif selected_cipher == "ChaCha20":
                        key = get_random_bytes(32)
                        conn.send(key)  # Send the key as binary data
                        print(f"[{addr}] Sent key: {key.hex()}")
                elif msg == DISCONNECT_MESSAGE:
                    connected = False
                else:
                    print(f"[{addr}] {msg}")
        except Exception as e:
            print(f"[ERROR] {e}")
            connected = False
    
    conn.close()
    print(f"[DISCONNECTED] {addr} disconnected.")

def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}") 

print("[STARTING] server is starting...")
start()