import socket
import time
from Cryptodome.Cipher import Salsa20, ChaCha20
import json
from base64 import b64encode, b64decode

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = "192.168.1.14"  # Asegúrate de que esta IP sea la del servidor
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def send(msg):
    """Enviar un mensaje formateado al servidor."""
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)

def send_bytes(data):
    """Enviar bytes sin formatear al servidor."""
    msg_length = len(data)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(data)

def receive():
    """Recibe un mensaje formateado del servidor."""
    try:
        msg_length = client.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length.strip())
            msg = client.recv(msg_length).decode(FORMAT)
            return msg
    except Exception as e:
        print(f"Error receiving message: {e}")
    return None

def receive_bytes():
    """Recibe datos en bruto del servidor sin decodificar."""
    try:
        msg_length = client.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length.strip())
            data = client.recv(msg_length)
            return data
    except Exception as e:
        print(f"Error receiving bytes: {e}")
    return None

def log_performance(algorithm, operation, duration):
    """
    Registra los tiempos de operación (encriptación/descifrado) en un archivo CSV.
    Cada línea tendrá: algoritmo, operación, duración (segundos).
    """
    with open("performance_log.csv", "a") as file:
        file.write(f"{algorithm},{operation},{duration}\n")

def encrypted_chat(cipher_type, key):
    """Establece una sesión de chat cifrado con el servidor, midiendo tiempos de cifrado y descifrado."""
    print("\n--- Encrypted Chat Started ---")
    print("Escribe tus mensajes y presiona Enter para enviar.")
    print("Escribe 'end' para desconectar.")
    chat_active = True
    while chat_active:
        user_input = input("You: ")
        if user_input.lower() == "end":
            print("Enviando mensaje de desconexión y finalizando chat...")
            user_input = "end"
            chat_active = False

        if cipher_type == "Salsa20":
            start_enc = time.perf_counter()
            cipher = Salsa20.new(key=key)
            plaintext = user_input.encode(FORMAT)
            encrypted = cipher.encrypt(plaintext)
            # Concatenamos el nonce y el ciphertext antes de finalizar la medición
            msg = cipher.nonce + encrypted
            end_enc = time.perf_counter()
            enc_time = end_enc - start_enc
            log_performance(cipher_type, "encryption", enc_time)

        elif cipher_type == "ChaCha20":
            start_enc = time.perf_counter()
            cipher = ChaCha20.new(key=key)
            plaintext = user_input.encode(FORMAT)
            ciphertext = cipher.encrypt(plaintext)
            nonce = b64encode(cipher.nonce).decode('utf-8')
            ct = b64encode(ciphertext).decode('utf-8')
            result = json.dumps({'nonce': nonce, 'ciphertext': ct})
            # Se mide hasta después de crear la cadena JSON
            msg = result.encode('utf-8')
            end_enc = time.perf_counter()
            enc_time = end_enc - start_enc
            log_performance(cipher_type, "encryption", enc_time)
            print(f"Encrypted message: {msg}")
        
        print("sent")
        send_bytes(msg)
        if not chat_active:
            break

        # Recepción y descifrado de la respuesta del servidor
        if cipher_type == "Salsa20":
            response = receive_bytes()
            print(f"Server response: {response}")
            msg_nonce = response[:8]
            ciphertext = response[8:]
            start_dec = time.perf_counter()
            cipher = Salsa20.new(key=key, nonce=msg_nonce)
            plaintext = cipher.decrypt(ciphertext)
            text = plaintext.decode(FORMAT)
            end_dec = time.perf_counter()
            dec_time = end_dec - start_dec
            log_performance(cipher_type, "decryption", dec_time)
            print(f"Decrypted message: {text}")
            if text == DISCONNECT_MESSAGE:
                chat_active = False
        else:
            response = receive_bytes()
            print(f"Server response: {response}")
            json_input = response.decode(FORMAT)
            try:
                start_dec = time.perf_counter()
                b64 = json.loads(json_input)
                nonce = b64decode(b64['nonce'])
                ciphertext = b64decode(b64['ciphertext'])
                cipher = ChaCha20.new(key=key, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext)
                text = plaintext.decode(FORMAT)
                end_dec = time.perf_counter()
                dec_time = end_dec - start_dec
                log_performance(cipher_type, "decryption", dec_time)
                print("The message was: ", text)
            except (ValueError, KeyError):
                print("Incorrect decryption")
            if text == DISCONNECT_MESSAGE:
                chat_active = False

def select_cipher():
    """Gestiona la selección del cifrador por parte del cliente."""
    prompt = receive()
    if not prompt:
        print("No se recibió respuesta del servidor. La conexión pudo haberse perdido.")
        return None
    
    try:
        cipher = int(input(prompt))
        if cipher == 1:
            cipher = "Salsa20"
            try:
                size = int(input("Selecciona el tamaño de la llave (1: 128 bits, 2: 256 bits): "))
                if size == 1:
                    key_size = 16
                elif size == 2:
                    key_size = 32
                else:
                    print("Tamaño inválido. Ingresa 1 o 2.")
                    return select_cipher()
            except ValueError:
                print("Entrada inválida. Ingresa un número.")
                return select_cipher()
        elif cipher == 2:
            cipher = "ChaCha20"
            size = 2  # Para ChaCha20 se usa llave de 32 bytes
            key_size = 32
        else:
            print("Selección inválida. Escoge 1 o 2.")
            return select_cipher()
    except ValueError:
        print("Entrada inválida. Ingresa un número.")
        return select_cipher()
    
    send(f"CIPHER:{cipher}") 
    if cipher == "Salsa20":
        prompt = receive()
        if not prompt:
            print("No se recibió respuesta del servidor tras enviar la elección del cifrado.")
            return None
        else: 
            send(f"{size}")
   
    key = receive_bytes()
    if key:
        print(f"Received key: {key}")
        encrypted_chat(cipher, key)
        return cipher, key, size
    else:
        print("No se pudo recibir la llave del servidor")
        return None

def display_menu():
    """Muestra el menú principal y solicita la opción del usuario."""
    print("\n===== ENCRYPTED COMMUNICATION CLIENT =====")
    print("1. Iniciar sesión de comunicación segura")
    print("2. Salir")
    
    try:
        choice = int(input("\nSelecciona una opción (1-2): "))
        if choice in [1, 2]:
            return choice
        else:
            print("Opción inválida. Selecciona 1 o 2.")
            return display_menu()
    except ValueError:
        print("Por favor, ingresa un número.")
        return display_menu()

# Ejecución principal
try:
    option = display_menu()
    if option == 1:
        result = select_cipher()
        if result:
            cipher, key, size = result
            print(f"\nProtocolo de cifrado establecido exitosamente:")
            print(f"- Algoritmo: {cipher}")
            print(f"- Tamaño de llave: {size} ({16 if size == 1 else 32} bytes)")
    elif option == 2:
        print("Saliendo de la aplicación...")
except Exception as e:
    print(f"Ocurrió un error: {e}")
finally:
    client.close()
    print("Conexión cerrada.")
