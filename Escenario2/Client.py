import socket
import os
from Crypto.Cipher import AES

# Leer clave compartida desde archivo
with open("clave_secreta.key", "rb") as file:
    clave_aes = file.read()

# Crear socket del Cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 12345))

# Elegir modo de operación y técnica de seguridad
modo_aes = "CBC"
tecnica_seguridad = "ninguna"

# Enviar los parámetros al Servidor
mensaje = f"{modo_aes},{tecnica_seguridad}"
client_socket.sendall(mensaje.encode())

print("Modo AES y técnica de seguridad enviados.")

# Si el Servidor envía claves adicionales, recibirlas
if tecnica_seguridad in ["cifrado doble", "cifrado triple"]:
    datos = client_socket.recv(1024)
    iv, claves_cifradas = datos[:16], datos[16:]

    # Descifrar claves adicionales
    cipher = AES.new(clave_aes, AES.MODE_CBC, iv)
    claves_descifradas = cipher.decrypt(claves_cifradas).strip()

    print(f"Claves adicionales recibidas y descifradas: {claves_descifradas.hex()}")

# Enviar mensaje cifrado al Servidor
mensaje = "Hola Servidor!".ljust(32)  # Padding
iv = os.urandom(16)
cipher = AES.new(clave_aes, AES.MODE_CBC, iv)
mensaje_cifrado = cipher.encrypt(mensaje.encode())

# Enviar IV + mensaje cifrado
client_socket.sendall(iv + mensaje_cifrado)

print("Mensaje cifrado enviado.")

client_socket.close()