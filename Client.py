# Import socket module 
import socket             

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = "192.168.1.62"  # Make sure this is your server's IP
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

def receive_exact_bytes(num_bytes):
    """Receive exactly num_bytes from the server"""
    data = b''
    bytes_received = 0
    while bytes_received < num_bytes:
        packet = client.recv(num_bytes - bytes_received)
        if not packet:
            return None
        data += packet
        bytes_received += len(packet)
    return data

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
        elif cipher == 2:
            cipher = "ChaCha20"
        else:
            print("Invalid selection. Please choose 1 or 2.")
            return select_cipher()
    except ValueError:
        print("Invalid input. Please enter a number.")
        return select_cipher()
    
    # Send cipher choice to server
    send(f"CIPHER:{cipher}")
    
    # Wait for key size prompt
    prompt = receive()
    if not prompt:
        print("No response from server after sending cipher choice.")
        return None
    
    # Handle key size selection
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
    
    # Send size choice to server
    send(f"{size}")
    
    # Receive key from server
    key = receive_exact_bytes(key_size)
    if key:
        print(f"Received key: {key.hex()}")
        
        return cipher, key, size
    else:
        print("Failed to receive key from server")
        return None

# Main execution
try:
    result = select_cipher()
    if result:
        cipher, key, size = result
        print(f"\nCipher protocol established successfully:")
        print(f"- Algorithm: {cipher}")
        print(f"- Key size: {size} ({16 if size == 1 else 32} bytes)")
    
    # Send disconnect message when done
    send(DISCONNECT_MESSAGE)
except Exception as e:
    print(f"An error occurred: {e}")