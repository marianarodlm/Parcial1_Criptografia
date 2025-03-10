# Import socket module 
import socket             
from Cryptodome.Cipher import Salsa20, ChaCha20
import json
from base64 import b64encode, b64decode

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = "192.168.1.14"  # Make sure this is your server's IP
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def send(msg):
    """Send a formatted message to the server"""
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)

def send_bytes(data):
    """Send raw bytes to the server"""
    msg_length = len(data)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(data)  # Send bytes directly

def receive():
    """Receive a message from the server using the defined protocol"""
    try:
        # First get the message length from the header
        msg_length = client.recv(HEADER).decode(FORMAT)
        if msg_length:
            # Convert the length to an integer after stripping any whitespace
            msg_length = int(msg_length.strip())
            # Receive the actual message
            msg = client.recv(msg_length).decode(FORMAT)
            return msg
    except Exception as e:
        print(f"Error receiving message: {e}")
    return None


def receive_bytes():
    """Receive raw bytes from the server"""
    try:
        msg_length = client.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length.strip())
            data = client.recv(msg_length)  # Don't decode
            return data
    except Exception as e:
        print(f"Error receiving bytes: {e}")
    return None

def encrypted_chat(cipher_type, key):
    """Establish an encrypted chat session with the server"""
    print("\n--- Encrypted Chat Started ---")
    print("Type your messages and press Enter to send.")
    print("Type 'end' to disconnect.")
    chat_active = True
    while chat_active:
        user_input = input("You: ")
        if user_input.lower() == "end":
             # Enviar mensaje de desconexión cifrado antes de salir
            print("Sending disconnect message and ending chat...")
            chat_active = False  # Salir del ciclo inmediatamente
        if cipher_type == "Salsa20":
            cipher = Salsa20.new(key=key)
            plaintext = user_input.encode(FORMAT)
            msg = cipher.nonce + cipher.encrypt(plaintext)
        elif cipher_type == "ChaCha20":
            cipher = ChaCha20.new(key=key)
            plaintext = user_input.encode(FORMAT)
            ciphertext = cipher.encrypt(plaintext)
            nonce = b64encode(cipher.nonce).decode('utf-8')
            ct = b64encode(ciphertext).decode('utf-8')
            result = json.dumps({'nonce': nonce, 'ciphertext': ct})
            msg = result.encode('utf-8') 
            print(f"Encrypted message: {msg}")  

# Convert the JSON string into a bytes object

        print("sent")
        send_bytes(msg)
        if chat_active == False:
            break
        if cipher_type == "Salsa20":
            response = receive_bytes()
            print(f"Server response: {response}")
            msg_nonce = response[:8]
            ciphertext = response[8:]
            cipher = Salsa20.new(key=key, nonce=msg_nonce)
            plaintext = cipher.decrypt(ciphertext)
            text = plaintext.decode(FORMAT)
            print(f"Decrypted message: {text}")
            if text==DISCONNECT_MESSAGE:
                chat_active = False
        else:
            response = receive_bytes()
            print(f"Server response: {response}")
            json_input = response.decode(FORMAT)
            try:
                b64 = json.loads(json_input)
                nonce = b64decode(b64['nonce'])
                ciphertext = b64decode(b64['ciphertext'])
                cipher = ChaCha20.new(key=key, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext)
                print("The message was: ",plaintext.decode(FORMAT))
            except (ValueError, KeyError):
                print("Incorrect decryption")
            text = plaintext.decode(FORMAT)
            if text==DISCONNECT_MESSAGE:
                chat_active = False
            
            
def select_cipher():
    """Handle cipher selection process with server"""
    # Wait for initial prompt from server
    prompt = receive()
    if not prompt:
        print("No response from server. Connection may be lost.")
        return None
    
    # Handle cipher selection
    try:
        cipher = int(input(prompt))
        if cipher == 1:
            cipher = "Salsa20"
            try:
                size = int(input(prompt))
                if size == 1:
                    key_size = 16
                elif size == 2:
                    key_size = 32
                else:
                    print("Invalid size. Please enter 1 or 2.")
                    # Recursively try again
                    return select_cipher()
            except ValueError:
                print("Invalid input. Please enter a number.")
                return select_cipher()
        elif cipher == 2:
            cipher = "ChaCha20"
            key_size = 32
            
        else:
            print("Invalid selection. Please choose 1 or 2.")
            return select_cipher()
    except ValueError:
        print("Invalid input. Please enter a number.")
        return select_cipher()
    
    # Send cipher choice to server
    send(f"CIPHER:{cipher}") 
    # Wait for key size prompt
    if cipher=="Salsa20":
        prompt = receive()
        if not prompt:
            print("No response from server after sending cipher choice.")
            return None
        else: 
             send(f"{size}")
   
    # Receive key from server
    key = receive_bytes()
    if key:
        print(f"Received key: {key}")
        # Add a conversation option between Client and server after the key is received
        encrypted_chat(cipher, key)
        return cipher, key, size
    else:
        print("Failed to receive key from server")
        return None

def display_menu():
    """Display the main menu and get user choice"""
    print("\n===== ENCRYPTED COMMUNICATION CLIENT =====")
    print("1. Start secure communication session")
    print("2. Exit")
    
    try:
        choice = int(input("\nSelect an option (1-2): "))
        if choice in [1, 2]:
            return choice
        else:
            print("Invalid option. Please select 1 or 2.")
            return display_menu()
    except ValueError:
        print("Please enter a number.")
        return display_menu()

# Main execution
try:
    option = display_menu()
    
    if option == 1:
        # Existing functionality
        result = select_cipher()
        if result:
            cipher, key, size = result
            print(f"\nCipher protocol established successfully:")
            print(f"- Algorithm: {cipher}")
            print(f"- Key size: {size} ({16 if size == 1 else 32} bytes)")
        
        # No need to send DISCONNECT_MESSAGE again, it's handled in encrypted_chat
    
    elif option == 2:
        print("Exiting application...")
        pass  # Just exit without doing anything else
        
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    client.close()
    print("Connection closed.")