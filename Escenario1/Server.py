import socket 
import json
from base64 import b64decode, b64encode
import threading 
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import Salsa20, ChaCha20
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad 

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
                if text == "end":
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

def encrypted_chat2(client, cipher_type, key, security_option):
    print("\n--- Encrypted Chat Started ---")
    while True:
        if security_option == "1":
            response = client.receive_bytes()
            json_input = response.decode(FORMAT)
            if cipher_type == "ECB":
                try:
                    b64 = json.loads(json_input)
                    iv = b64decode(b64['iv'])
                    ct = b64decode(b64['ciphertext'])
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    print("The message was: ", pt)
                except (ValueError, KeyError):
                    print("Incorrect decryption")
            elif cipher_type == "CBC":
                try:
                    b64 = json.loads(json_input)
                    iv = b64decode(b64['iv'])
                    ct = b64decode(b64['ciphertext'])
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    print("The message was: ", pt)
                except (ValueError, KeyError):
                    print("Incorrect decryption")
            else: # CTR 
                try:
                    b64 = json.loads(json_input)
                    nonce = b64decode(b64['nonce'])
                    ct = b64decode(b64['ciphertext'])
                    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                    pt = cipher.decrypt(ct)
                    print("The message was: ", pt)
                except (ValueError, KeyError):
                    print("Incorrect decryption")
        
            user_input = input("SERVER: ")
            if user_input == DISCONNECT_MESSAGE:
                send_message(client, DISCONNECT_MESSAGE)
                break
            if cipher_type == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
                ct_bytes = cipher.encrypt(pad(user_input, AES.block_size))
                iv = b64encode(cipher.iv).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({'iv':iv, 'ciphertext':ct})
            elif cipher_type == "CBC":
                cipher = AES.new(key, AES.MODE_CBC)
                ct_bytes = cipher.encrypt(pad(user_input, AES.block_size))
                iv = b64encode(cipher.iv).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({'iv':iv, 'ciphertext':ct})
            else: # CTR
                cipher = AES.new(key, AES.MODE_CTR)
                ct_bytes = cipher.encrypt(user_input)
                nonce = b64encode(cipher.nonce).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({'nonce':nonce, 'ciphertext':ct})

            msg = result.encode('utf-8')
            print("sent")
            client.send_bytes(msg)
            
        if security_option == "2":
            key2 = get_random_bytes(32)
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(key2, AES.block_size))
            iv = b64encode(cipher.iv).decode('utf-8')
            ct = b64encode(ct_bytes).decode('utf-8')
            result = json.dumps({'iv':iv, 'ciphertext':ct})
            msg = result.encode(FORMAT)
            client.send_bytes(msg)
            # Recibir confirmación del cliente
            
            

    
def send_key_drive():
    # Obtener la ruta absoluta del directorio del script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Especificar la ruta completa al archivo client_secrets.json
    client_secrets_path = os.path.join(script_dir, "client_secrets.json")
    
    # Configurar GoogleAuth con la ruta explícita
    gauth = GoogleAuth()
    gauth.settings['client_config_file'] = client_secrets_path
    gauth.LocalWebserverAuth()
    
    drive = GoogleDrive(gauth)

    # Obtener la ruta completa al archivo de clave
    ruta_archivo = os.path.join(script_dir, 'aes_key.bin')
    nombre_drive = 'llave_a_compartir.key'

    # Buscar si el archivo ya existe en Drive
    file_list = drive.ListFile({'q': f"title='{nombre_drive}'"}).GetList()
    
    if file_list:
        archivo_drive = file_list[0]
        print("Archivo existente encontrado, será actualizado.")
    else:
        archivo_drive = drive.CreateFile({'title': nombre_drive})
        print("Creando nuevo archivo en Drive.")

    archivo_drive.SetContentFile(ruta_archivo)
    archivo_drive.Upload()
    print("Archivo subido correctamente a Google Drive.")
    
def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    
    #execute this only if client chooses option 1
    client_choice = receive_message(conn)
    if client_choice == "1":
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
                    elif selected_cipher == "BLOCK":
                        print(f"[{addr}] Selected block cipher")
                        key = get_random_bytes(32)
                        # Enviar la clave al cliente usando la función send_bytes
                        script_dir = os.path.dirname(os.path.abspath(__file__))

                        aes_key_path = os.path.join(script_dir, "aes_key.bin")

                        # Ahora usar esta ruta para guardar el archivo
                        with open(aes_key_path, "wb") as f:
                            f.write(key)
                        send_key_drive()
                        print(f"[{addr}] Sent block cipher key: {key.hex()}")
                        try:
                            os.remove(aes_key_path)
                            print(f"[SECURITY] Archivo local {aes_key_path} eliminado por seguridad.")
                        except Exception as e:
                            print(f"[WARNING] No se pudo eliminar el archivo local: {e}")
                            
                        send_message(conn, "1")
                    try:
                        # Esperar a que el cliente indique que ha recibido la clave
                        msg = receive_message(conn)
                        if msg == "KEY_RECEIVED":
                            print(f"[{addr}] Client confirmed key reception")
                            
                            # Enviar prompt al cliente para seleccionar el modo de cifrado
                            send_message(conn, "PROMPT: Select the AES encryption mode (1: ECB, 2: CBC, 3: CTR):")
                            
                            # Recibir la selección del cliente
                            aes_option = receive_message(conn)
                            if aes_option and aes_option.startswith("AES_MODE:"):
                                selected_mode = aes_option[9:]  # Extraer la opcion después de "AES_MODE:"
                                print(f"[{addr}] Selected AES mode: {selected_mode}")
                                send_message(conn, "PROMPT: Select the security technique addition (1: None, 2: Double cipher, 3: Triple cipher 4.Key whitening):")
                                security_option = receive_message(conn)
                                # recibir opción
                                encrypted_chat2(conn, selected_mode, key,security_option)
                    except Exception as e:
                     print(f"[ERROR in handle_client2] {e}")
                    finally:
                      conn.close()
                      print(f"[DISCONNECTED] {addr} disconnected.")

                    # Solo llamar a encrypted_chat para Salsa20 y ChaCha20
                    if selected_cipher in ["Salsa20", "ChaCha20"]:
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