import socket
import secrets
import os
from Crypto.Cipher import AES

# Generar clave AES de 256 bits
clave_aes = secrets.token_bytes(32)

# Guardar clave en un archivo para compartirla por un canal alterno
with open("clave_secreta.key", "wb") as file:
    file.write(clave_aes)

print(f"Clave AES generada: {clave_aes.hex()}")
print("Comparta este archivo con el Cliente por un canal alterno.")

# Crear socket del Servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 12345))
server_socket.listen(1)

print("Esperando conexión del Cliente...")
client_socket, addr = server_socket.accept()
print(f"Cliente conectado desde {addr}")

# Recibir modo de operación y técnica de seguridad
mensaje = client_socket.recv(1024).decode()
modo_aes, tecnica_seguridad = mensaje.split(",")

print(f"Modo AES elegido: {modo_aes}")
print(f"Técnica de seguridad: {tecnica_seguridad}")

# Si el Cliente elige cifrado doble/triple, generar claves adicionales
if tecnica_seguridad in ["cifrado doble", "cifrado triple"]:
    claves_adicionales = secrets.token_bytes(32)  # Nueva clave aleatoria

    # Cifrar claves adicionales con AES-CBC antes de enviarlas
    iv = os.urandom(16)
    cipher = AES.new(clave_aes, AES.MODE_CBC, iv)
    claves_cifradas = cipher.encrypt(claves_adicionales.ljust(32))  # Padding

    # Enviar IV + claves cifradas al Cliente
    client_socket.sendall(iv + claves_cifradas)

# Recibir mensaje cifrado del Cliente
datos = client_socket.recv(1024)
iv, mensaje_cifrado = datos[:16], datos[16:]

# Descifrar mensaje
cipher = AES.new(clave_aes, AES.MODE_CBC, iv)
mensaje_descifrado = cipher.decrypt(mensaje_cifrado).strip().decode()

print(f"Mensaje recibido (descifrado): {mensaje_descifrado}")

client_socket.close()
server_socket.close()