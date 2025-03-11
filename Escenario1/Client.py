import time
from Cryptodome.Cipher import Salsa20, ChaCha20
import json
from base64 import b64encode, b64decode
# Import the Client class from ClientClass.py
from ClientClass import Client
import os
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive

# Constants for the client configuration
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = '192.168.1.10'  # Asegúrate de que esta IP sea la del servidor
PORT = 5050

def log_performance(algorithm, operation, duration):
    """
    Registra los tiempos de operación (encriptación/descifrado) en un archivo CSV.
    Cada línea tendrá: algoritmo, operación, duración (segundos).
    """
    with open("performance_log.csv", "a") as file:
        file.write(f"{algorithm},{operation},{duration}\n")

def encrypted_chat(client, cipher_type, key):
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
        client.send_bytes(msg)
        if not chat_active:
            break

        # Recepción y descifrado de la respuesta del servidor
        if cipher_type == "Salsa20":
            response = client.receive_bytes()
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
            response = client.receive_bytes()
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

def select_cipher(client):
    """Gestiona la selección del cifrador por parte del cliente."""
    prompt = client.receive()
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
                    return select_cipher(client)
            except ValueError:
                print("Entrada inválida. Ingresa un número.")
                return select_cipher(client)
        elif cipher == 2:
            cipher = "ChaCha20"
            size = 2  # Para ChaCha20 se usa llave de 32 bytes
            key_size = 32
        else:
            print("Selección inválida. Escoge 1 o 2.")
            return select_cipher(client)
    except ValueError:
        print("Entrada inválida. Ingresa un número.")
        return select_cipher(client)
    
    client.send(f"CIPHER:{cipher}") 
    if cipher == "Salsa20":
        prompt = client.receive()
        if not prompt:
            print("No se recibió respuesta del servidor tras enviar la elección del cifrado.")
            return None
        else: 
            client.send(f"{size}")
   
    key = client.receive_bytes()
    if key:
        print(f"Received key: {key.hex()}")  # Using hex() for better display
        encrypted_chat(client, cipher, key)
        return cipher, key, size
    else:
        print("No se pudo recibir la llave del servidor")
        return None
    
def cipher_block():
    """Handle block cipher selection process with server"""
    # Send message to server indicating we want to use a block cipher
    client.send("CIPHER:BLOCK")
    response = client.receive()
    print("Received response from server:", response)
    if response!="1":
        print("Server did not accept block cipher request")
        return None
    key = download_key_from_drive() 
    if key:
        print(f"Received block cipher key: {key.hex()}")
        return "Block Cipher", key, 2  # Size 2 represents 256 bits
    else:
        print("Failed to receive key from server")
        return None
    
def download_key_from_drive():
    """
    Descarga el archivo de clave AES desde Google Drive
    """
    # Obtener la ruta absoluta del directorio del script
    script_dir = os.path.dirname(os.path.abspath(_file_))
    
    # Especificar la ruta completa al archivo client_secrets.json
    client_secrets_path = os.path.join(script_dir, "client_secrets.json")
    
    # Configurar GoogleAuth con la ruta explícita
    gauth = GoogleAuth()
    gauth.settings['client_config_file'] = client_secrets_path
    gauth.LocalWebserverAuth()
    
    drive = GoogleDrive(gauth)

    # Nombre del archivo a buscar en Drive
    nombre_drive = 'llave_a_compartir.key'

    # Buscar el archivo en Drive
    file_list = drive.ListFile({'q': f"title='{nombre_drive}'"}).GetList()
    
    if not file_list:
        print(f"Error: No se encontró el archivo '{nombre_drive}' en Google Drive")
        return None
    
    # Obtener el primer archivo que coincida
    archivo_drive = file_list[0]
    print(f"Archivo encontrado en Drive: {archivo_drive['title']}")
    
    # Definir la ruta donde se guardará el archivo descargado
    ruta_destino = os.path.join(script_dir, 'aes_key_received.bin')
    
    # Descargar el archivo
    archivo_drive.GetContentFile(ruta_destino)
    print(f"Archivo descargado correctamente a: {ruta_destino}")
    
    # Verificar que se descargó correctamente
    if os.path.exists(ruta_destino):
        # Leer el contenido del archivo (la clave)
        with open(ruta_destino, 'rb') as f:
            key = f.read()
        print(f"Clave AES recuperada ({len(key)} bytes)")
        return key
    else:
        print("Error: No se pudo descargar el archivo")
        return None

def display_menu():
    """Muestra el menú principal y solicita la opción del usuario."""
    print("\n===== ENCRYPTED COMMUNICATION CLIENT =====")
    print("1. Iniciar sesión de comunicación segura")
    print("2. Cifrador de bloque")
    
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
    # Create a client instance
    client = Client(server_ip=SERVER, port=PORT)
    
    option = display_menu()
    client.send(f"{option}")
    if option == 1:
        result = select_cipher(client)
        if result:
            cipher, key, size = result
            print(f"\nProtocolo de cifrado establecido exitosamente:")
            print(f"- Algoritmo: {cipher}")
            print(f"- Tamaño de llave: {size} ({16 if size == 1 else 32} bytes)")
    elif option == 2:
        print("Requestig block cipher from server")
        result = cipher_block()
        if result:
            cipher, key, size = result
            print(f"\nBlock cipher protocol established successfully:")
            print(f"- Algorithm: {cipher}")
            print(f"- Key size: {size} ({16 if size == 1 else 32} bytes)")
except Exception as e:
    print(f"Ocurrió un error: {e}")
finally:
    # Make sure we close the client connection
    if 'client' in locals():
        client.close()