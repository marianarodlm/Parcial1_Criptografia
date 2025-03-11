import socket 
import json
from base64 import b64decode, b64encode
import threading 
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import Salsa20, ChaCha20

HEADER = 64
PORT = 5050
SERVER= "0.0.0.0"
#SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


def send_bytes(conn, data):
    """Send raw bytes to the client"""
    msg_length = len(data)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    conn.send(send_length)
    conn.send(data)  # Send bytes directly
    
    
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

def receive_bytes(conn):
    """Receive binary data from the client without decoding"""
    msg_length = conn.recv(HEADER).decode(FORMAT)
    if msg_length:
        msg_length = int(msg_length.strip())
        data = conn.recv(msg_length)  # Don't decode as UTF-8
        print(f"[DEBUG] Received bytes: {data}")
        return data
    return None

def encrypted_chat(conn, cipher_type, key):
    """Receive a message from the client, decrypt it, then encrypt the server's response"""
    print("\n--- Encrypted Chat Started ---")
    while True:
        msg= receive_bytes(conn)
        print(f"[DEBUG] Encrypted chat received message: {msg}")
        if msg:
            if cipher_type == "Salsa20":
                # Extract nonce (first 8 bytes) and ciphertext
                msg_nonce = msg[:8]
                ciphertext = msg[8:]
                # Create cipher with the same key and nonce
                cipher = Salsa20.new(key=key, nonce=msg_nonce)
                decrypted = cipher.decrypt(ciphertext)
                text = decrypted.decode(FORMAT)
                print(f"[CLIENT] {text}")
                if text == DISCONNECT_MESSAGE:
                    break
                
                # Send response
                message = input("SERVER: ")
                if message == DISCONNECT_MESSAGE:
                    send_message(conn, DISCONNECT_MESSAGE)
                    break
                    
                # Create new cipher for encryption (generates new nonce)
                cipher = Salsa20.new(key=key)
                # Send nonce + encrypted message
                encrypted = cipher.nonce + cipher.encrypt(message.encode(FORMAT))
                print(type(encrypted))
                send_bytes(conn, encrypted)
            elif cipher_type == "ChaCha20":
                json_input = msg.decode(FORMAT)
                try:
                    b64 = json.loads(json_input)
                    nonce = b64decode(b64['nonce'])
                    ciphertext = b64decode(b64['ciphertext'])
                    cipher = ChaCha20.new(key=key, nonce=nonce)
                    plaintext = cipher.decrypt(ciphertext)
                    print("The message was: ",plaintext.decode(FORMAT))
                    if plaintext.decode(FORMAT) == "end":
                        break
                except (ValueError, KeyError):
                    print("Incorrect decryption")
                
                
                message = input("SERVER: ")
                if message == DISCONNECT_MESSAGE:
                    send_message(conn, DISCONNECT_MESSAGE)
                    break
                
                cipher = ChaCha20.new(key=key)
                plaintext = message.encode(FORMAT)
                ciphertext = cipher.encrypt(plaintext)

                nonce = b64encode(cipher.nonce).decode('utf-8')
                ct = b64encode(ciphertext).decode('utf-8')
                result = json.dumps({'nonce':nonce, 'ciphertext':ct})
                msg = result.encode(FORMAT)
                send_bytes(conn, msg)


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
                        size = int(size)
                        if size == 1:
                            key = get_random_bytes(16)
                        elif size == 2:
                            key = get_random_bytes(32)
                        if key:
                            # Use send_bytes instead of direct conn.send
                            send_bytes(conn, key)
                            print(f"[{addr}] Sent key: {key.hex()}")
                    elif selected_cipher == "ChaCha20":
                        key = get_random_bytes(32)
                        # Use send_bytes instead of direct conn.send
                        send_bytes(conn, key)
                        print(f"[{addr}] Sent key: {key.hex()}")
                    encrypted_chat(conn, selected_cipher, key)
                    break
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