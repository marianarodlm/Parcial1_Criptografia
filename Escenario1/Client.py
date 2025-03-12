import time
from Cryptodome.Cipher import Salsa20, ChaCha20
import json
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad 
# Import the Client class from ClientClass.py
from ClientClass import Client
import os
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive

# Constants for the client configuration
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = '192.168.1.62'  # Asegúrate de que esta IP sea la del servidor
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

def encrypted_chat2(client, selected_mode, key, choice_security):
    """Establece una sesión de chat cifrado con el servidor, midiendo tiempos de cifrado y descifrado."""
    print("\n--- Encrypted Chat Started ---")
    print("Escribe tus mensajes y presiona Enter para enviar.")
    print("Escribe 'end' para desconectar.")
    chat_active = True
    print(type(choice_security))
    print(choice_security)
    while chat_active:
        user_input = input("You: ")
        if user_input.lower() == "end":
            print("Enviando mensaje de desconexión y finalizando chat...")
            user_input = "end"
            chat_active = False
        if choice_security == "1":
            # ENVIAR MENSAJE CIFRADO AL SERVIDOR
            if selected_mode == "ECB":
                plaintext = user_input.encode(FORMAT)
                cipher = AES.new(key, AES.MODE_ECB)
                # Ahora aplicar padding al objeto bytes
                ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({'ciphertext':ct})
            elif selected_mode == "CBC":
                user_input = user_input.encode(FORMAT)
                cipher = AES.new(key, AES.MODE_CBC)
                ct_bytes = cipher.encrypt(pad(user_input, AES.block_size))
                iv = b64encode(cipher.iv).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({'iv':iv, 'ciphertext':ct})
            else: # CTR
                user_input = user_input.encode(FORMAT)
                cipher = AES.new(key, AES.MODE_CTR)
                ct_bytes = cipher.encrypt(user_input)
                nonce = b64encode(cipher.nonce).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({'nonce':nonce, 'ciphertext':ct})

            msg = result.encode('utf-8')
            print("sent")
            client.send_bytes(msg)
            if not chat_active:
                break

            response = client.receive_bytes()
            json_input = response.decode(FORMAT)
            # RECIBIR MENSAJE CIFRADO DEL SERVIDOR Y DESCIFRAR
            if selected_mode == "ECB":
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    cipher = AES.new(key, AES.MODE_ECB)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError):
                    print("Incorrect decryption")
            elif selected_mode == "CBC":
                try:
                    b64 = json.loads(json_input)
                    iv = b64decode(b64['iv'])
                    ct = b64decode(b64['ciphertext'])
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError):
                    print("Incorrect decryption")
            else: # CTR 
                try:
                    b64 = json.loads(json_input)
                    nonce = b64decode(b64['nonce'])
                    ct = b64decode(b64['ciphertext'])
                    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                    pt = cipher.decrypt(ct)
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError):
                    print("Incorrect decryption")
        elif choice_security=="2":
            key2 = client.receive_bytes()
            json_input = key2.decode(FORMAT)
            try:
                b64 = json.loads(json_input)
                iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                key2 = unpad(cipher.decrypt(ct), AES.block_size)
            except (ValueError, KeyError):
                print("Incorrect decryption")
            
            if selected_mode == "ECB":
                plaintext = user_input.encode(FORMAT)
                cipher1 = AES.new(key, AES.MODE_ECB)
                intermediate = cipher1.encrypt(pad(plaintext, AES.block_size))
                
                # ENCRYPT: Segundo cifrado con key2
                cipher2 = AES.new(key2, AES.MODE_ECB)
                ct_bytes = cipher2.encrypt(intermediate)  # No necesita padding adicional
                
                # Codificar y formar el JSON
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({'ciphertext': ct})
                
                # Enviar mensaje doblemente cifrado
                msg = result.encode('utf-8')
                print("sent double-encrypted message")
                client.send_bytes(msg)
                
                response = client.receive_bytes()
                json_input = response.decode(FORMAT)
                
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    
                    # Primer descifrado con key2
                    cipher2_dec = AES.new(key2, AES.MODE_ECB)
                    intermediate_dec = cipher2_dec.decrypt(ct)
                    
                    # Segundo descifrado con key1
                    cipher1_dec = AES.new(key, AES.MODE_ECB)
                    pt = unpad(cipher1_dec.decrypt(intermediate_dec), AES.block_size)
                    
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError) as e:
                    print(f"Incorrect double decryption: {e}")
                    

            elif selected_mode == "CBC":
                 # ENCRYPT: Primer cifrado con key1
                plaintext = user_input.encode(FORMAT)
                cipher1 = AES.new(key, AES.MODE_CBC)
                iv1 = cipher1.iv  # Guardar IV del primer cifrado
                intermediate = cipher1.encrypt(pad(plaintext, AES.block_size))
                
                # ENCRYPT: Segundo cifrado con key2
                cipher2 = AES.new(key2, AES.MODE_CBC)
                iv2 = cipher2.iv  # Guardar IV del segundo cifrado
                ct_bytes = cipher2.encrypt(intermediate)  # No necesita padding adicional
                
                # Codificar y formar el JSON con ambos IVs
                iv1_b64 = b64encode(iv1).decode('utf-8')
                iv2_b64 = b64encode(iv2).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({
                    'iv1': iv1_b64, 
                    'iv2': iv2_b64, 
                    'ciphertext': ct
                })
                
                # Enviar mensaje doblemente cifrado
                msg = result.encode('utf-8')
                print("sent double-encrypted CBC message")
                client.send_bytes(msg)
    
                if not chat_active:
                    break
        
                # Recibir respuesta
                response = client.receive_bytes()
                json_input = response.decode(FORMAT)
                
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    iv2 = b64decode(b64['iv2'])
                    iv1 = b64decode(b64['iv1'])
                    
                    # Primer descifrado con key2
                    cipher2_dec = AES.new(key2, AES.MODE_CBC, iv=iv2)
                    intermediate_dec = cipher2_dec.decrypt(ct)
                    
                    # Segundo descifrado con key1
                    cipher1_dec = AES.new(key, AES.MODE_CBC, iv=iv1)
                    pt = unpad(cipher1_dec.decrypt(intermediate_dec), AES.block_size)
                    
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError) as e:
                    print(f"Incorrect double CBC decryption: {e}")
                    
                    
            elif selected_mode == "CTR":
                # ENCRYPT: Primer cifrado con key1
                plaintext = user_input.encode(FORMAT)
                cipher1 = AES.new(key, AES.MODE_CTR)
                nonce1 = cipher1.nonce  # Guardar nonce del primer cifrado
                intermediate = cipher1.encrypt(plaintext)  # CTR no requiere padding
                
                # ENCRYPT: Segundo cifrado con key2
                cipher2 = AES.new(key2, AES.MODE_CTR)
                nonce2 = cipher2.nonce  # Guardar nonce del segundo cifrado
                ct_bytes = cipher2.encrypt(intermediate)
                
                # Codificar y formar el JSON con ambos nonces
                nonce1_b64 = b64encode(nonce1).decode('utf-8')
                nonce2_b64 = b64encode(nonce2).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({
                    'nonce1': nonce1_b64, 
                    'nonce2': nonce2_b64, 
                    'ciphertext': ct
                })
                msg = result.encode('utf-8')
                print("sent double-encrypted CTR message")
                client.send_bytes(msg)
                
                if not chat_active:
                    break
                
                # Recibir respuesta
                response = client.receive_bytes()
                json_input = response.decode(FORMAT)
                
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    nonce2 = b64decode(b64['nonce2'])
                    nonce1 = b64decode(b64['nonce1'])
                    
                    # Primer descifrado con key2
                    cipher2_dec = AES.new(key2, AES.MODE_CTR, nonce=nonce2)
                    intermediate_dec = cipher2_dec.decrypt(ct)
                    
                    # Segundo descifrado con key1
                    cipher1_dec = AES.new(key, AES.MODE_CTR, nonce=nonce1)
                    pt = cipher1_dec.decrypt(intermediate_dec)  # CTR no requiere unpad
                    
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError) as e:
                    print(f"Incorrect double CTR decryption: {e}")
            
        elif choice_security=="3":
            # Recibir key2 y key3 del servidor
            key2 = client.receive_bytes()
            json_input = key2.decode(FORMAT)
            try:
                b64 = json.loads(json_input)
                iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                key2 = unpad(cipher.decrypt(ct), AES.block_size)
            except (ValueError, KeyError):
                print("Incorrect decryption")
            
            key3 = client.receive_bytes()
            json_input = key3.decode(FORMAT)
            try:
                b64 = json.loads(json_input)
                iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                key3 = unpad(cipher.decrypt(ct), AES.block_size)
            except (ValueError, KeyError):
                print("Incorrect decryption")
            
            if selected_mode == "ECB":
                # ENCRYPT: Primera capa con key1
                plaintext = user_input.encode(FORMAT)
                cipher1 = AES.new(key, AES.MODE_ECB)
                intermediate1 = cipher1.encrypt(pad(plaintext, AES.block_size))
                
                # ENCRYPT: Segunda capa con key2
                cipher2 = AES.new(key2, AES.MODE_ECB)
                intermediate2 = cipher2.encrypt(intermediate1)  # No necesita padding adicional
                
                # ENCRYPT: Tercera capa con key3
                cipher3 = AES.new(key3, AES.MODE_ECB)
                ct_bytes = cipher3.encrypt(intermediate2)  # No necesita padding adicional
                
                # Codificar y formar el JSON
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({'ciphertext': ct})
                
                # Enviar mensaje triplemente cifrado
                msg = result.encode('utf-8')
                print("sent triple-encrypted ECB message")
                client.send_bytes(msg)
                
                if not chat_active:
                    break
                    
                # Recibir respuesta del servidor
                response = client.receive_bytes()
                json_input = response.decode(FORMAT)
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    
                    # Descifrado en orden inverso
                    # Primer descifrado con key3
                    cipher3_dec = AES.new(key3, AES.MODE_ECB)
                    intermediate2_dec = cipher3_dec.decrypt(ct)
                    
                    # Segundo descifrado con key2
                    cipher2_dec = AES.new(key2, AES.MODE_ECB)
                    intermediate1_dec = cipher2_dec.decrypt(intermediate2_dec)
                    
                    # Tercer descifrado con key1
                    cipher1_dec = AES.new(key, AES.MODE_ECB)
                    pt = unpad(cipher1_dec.decrypt(intermediate1_dec), AES.block_size)
                    
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError) as e:
                    print(f"Incorrect triple ECB decryption: {e}")
            
            elif selected_mode == "CBC":
                # ENCRYPT: Primera capa con key1
                plaintext = user_input.encode(FORMAT)
                cipher1 = AES.new(key, AES.MODE_CBC)
                iv1 = cipher1.iv  # Guardar IV del primer cifrado
                intermediate1 = cipher1.encrypt(pad(plaintext, AES.block_size))
                
                # ENCRYPT: Segunda capa con key2
                cipher2 = AES.new(key2, AES.MODE_CBC)
                iv2 = cipher2.iv  # Guardar IV del segundo cifrado
                intermediate2 = cipher2.encrypt(intermediate1)
                
                # ENCRYPT: Tercera capa con key3
                cipher3 = AES.new(key3, AES.MODE_CBC)
                iv3 = cipher3.iv  # Guardar IV del tercer cifrado
                ct_bytes = cipher3.encrypt(intermediate2)
                
                # Codificar y formar el JSON con los tres IVs
                iv1_b64 = b64encode(iv1).decode('utf-8')
                iv2_b64 = b64encode(iv2).decode('utf-8')
                iv3_b64 = b64encode(iv3).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({
                    'iv1': iv1_b64, 
                    'iv2': iv2_b64, 
                    'iv3': iv3_b64,
                    'ciphertext': ct
                })
                
                # Enviar mensaje triplemente cifrado
                msg = result.encode('utf-8')
                print("sent triple-encrypted CBC message")
                client.send_bytes(msg)
                
                if not chat_active:
                    break
                    
                # Recibir respuesta
                response = client.receive_bytes()
                json_input = response.decode(FORMAT)
                
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    iv3 = b64decode(b64['iv3'])
                    iv2 = b64decode(b64['iv2'])
                    iv1 = b64decode(b64['iv1'])
                    
                    # Descifrado en orden inverso
                    # Primer descifrado con key3
                    cipher3_dec = AES.new(key3, AES.MODE_CBC, iv=iv3)
                    intermediate2_dec = cipher3_dec.decrypt(ct)
                    
                    # Segundo descifrado con key2
                    cipher2_dec = AES.new(key2, AES.MODE_CBC, iv=iv2)
                    intermediate1_dec = cipher2_dec.decrypt(intermediate2_dec)
                    
                    # Tercer descifrado con key1
                    cipher1_dec = AES.new(key, AES.MODE_CBC, iv=iv1)
                    pt = unpad(cipher1_dec.decrypt(intermediate1_dec), AES.block_size)
                    
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError) as e:
                    print(f"Incorrect triple CBC decryption: {e}")
                
            elif selected_mode == "CTR":
                # ENCRYPT: Primera capa con key1
                plaintext = user_input.encode(FORMAT)
                cipher1 = AES.new(key, AES.MODE_CTR)
                nonce1 = cipher1.nonce  # Guardar nonce del primer cifrado
                intermediate1 = cipher1.encrypt(plaintext)  # CTR no requiere padding
                
                # ENCRYPT: Segunda capa con key2
                cipher2 = AES.new(key2, AES.MODE_CTR)
                nonce2 = cipher2.nonce  # Guardar nonce del segundo cifrado
                intermediate2 = cipher2.encrypt(intermediate1)
                
                # ENCRYPT: Tercera capa con key3
                cipher3 = AES.new(key3, AES.MODE_CTR)
                nonce3 = cipher3.nonce  # Guardar nonce del tercer cifrado
                ct_bytes = cipher3.encrypt(intermediate2)
                
                # Codificar y formar el JSON con los tres nonces
                nonce1_b64 = b64encode(nonce1).decode('utf-8')
                nonce2_b64 = b64encode(nonce2).decode('utf-8')
                nonce3_b64 = b64encode(nonce3).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({
                    'nonce1': nonce1_b64, 
                    'nonce2': nonce2_b64, 
                    'nonce3': nonce3_b64,
                    'ciphertext': ct
                })
                
                # Enviar mensaje triplemente cifrado
                msg = result.encode('utf-8')
                print("sent triple-encrypted CTR message")
                client.send_bytes(msg)
                
                if not chat_active:
                    break
                
                # Recibir respuesta
                response = client.receive_bytes()
                json_input = response.decode(FORMAT)
                
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    nonce3 = b64decode(b64['nonce3'])
                    nonce2 = b64decode(b64['nonce2'])
                    nonce1 = b64decode(b64['nonce1'])
                    
                    # Descifrado en orden inverso
                    # Primer descifrado con key3
                    cipher3_dec = AES.new(key3, AES.MODE_CTR, nonce=nonce3)
                    intermediate2_dec = cipher3_dec.decrypt(ct)
                    
                    # Segundo descifrado con key2
                    cipher2_dec = AES.new(key2, AES.MODE_CTR, nonce=nonce2)
                    intermediate1_dec = cipher2_dec.decrypt(intermediate2_dec)
                    
                    # Tercer descifrado con key1
                    cipher1_dec = AES.new(key, AES.MODE_CTR, nonce=nonce1)
                    pt = cipher1_dec.decrypt(intermediate1_dec)  # CTR no requiere unpad
                    
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError) as e:
                    print(f"Incorrect triple CTR decryption: {e}")
                
        elif choice_security == "4":  # Key Whitening
            # Recibir clave de blanqueamiento del servidor
            key2 = client.receive_bytes()
            json_input = key2.decode(FORMAT)
            try:
                b64 = json.loads(json_input)
                iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                whitening_key = unpad(cipher.decrypt(ct), AES.block_size)
            except (ValueError, KeyError):
                print("Incorrect decryption")
            
            # Dividir la whitening key en dos partes
            wk_len = len(whitening_key) // 2
            pre_whitening = whitening_key[:wk_len]   # Para aplicar antes del cifrado
            post_whitening = whitening_key[wk_len:]  # Para aplicar después del cifrado
            
            if selected_mode == "ECB":
                # Convertir entrada a bytes
                plaintext = user_input.encode(FORMAT)
                
                # PASO 1: Pre-whitening - XOR con la primera parte de la whitening key
                # Asegurar que el plaintext tenga la longitud correcta para XOR
                padded_plaintext = pad(plaintext, AES.block_size)
                # Extender pre_whitening si es necesario para igualar longitud
                pre_w_extended = pre_whitening * (len(padded_plaintext) // len(pre_whitening) + 1)
                pre_w_extended = pre_w_extended[:len(padded_plaintext)]
                # Aplicar XOR byte a byte
                whitened_plaintext = bytes(a ^ b for a, b in zip(padded_plaintext, pre_w_extended))
                
                # PASO 2: Cifrado ECB estándar
                cipher = AES.new(key, AES.MODE_ECB)
                intermediate = cipher.encrypt(whitened_plaintext)
                
                # PASO 3: Post-whitening - XOR con la segunda parte de la whitening key
                post_w_extended = post_whitening * (len(intermediate) // len(post_whitening) + 1)
                post_w_extended = post_w_extended[:len(intermediate)]
                ct_bytes = bytes(a ^ b for a, b in zip(intermediate, post_w_extended))
                
                # Codificar y formar el JSON
                ct = b64encode(ct_bytes).decode('utf-8')
                # También incluir el identificador de whitening para el descifrado
                result = json.dumps({'ciphertext': ct, 'whitening': True})
                
                # Enviar mensaje con whitening
                msg = result.encode('utf-8')
                print("sent whitened-ECB message")
                client.send_bytes(msg)
                
                if not chat_active:
                    break
                
                # RECIBIR Y DESCIFRAR
                response = client.receive_bytes()
                json_input = response.decode(FORMAT)
                
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    
                    # PASO 1: Invertir post-whitening
                    post_w_extended = post_whitening * (len(ct) // len(post_whitening) + 1)
                    post_w_extended = post_w_extended[:len(ct)]
                    intermediate_dec = bytes(a ^ b for a, b in zip(ct, post_w_extended))
                    
                    # PASO 2: Descifrado ECB estándar
                    cipher = AES.new(key, AES.MODE_ECB)
                    whitened_plaintext_dec = cipher.decrypt(intermediate_dec)
                    
                    # PASO 3: Invertir pre-whitening
                    pre_w_extended = pre_whitening * (len(whitened_plaintext_dec) // len(pre_whitening) + 1)
                    pre_w_extended = pre_w_extended[:len(whitened_plaintext_dec)]
                    plaintext_padded = bytes(a ^ b for a, b in zip(whitened_plaintext_dec, pre_w_extended))
                    
                    # Quitar padding
                    pt = unpad(plaintext_padded, AES.block_size)
                    
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError) as e:
                    print(f"Incorrect whitening decryption: {e}")
            elif selected_mode == "CBC":
                # Convertir entrada a bytes
                plaintext = user_input.encode(FORMAT)
                
                # PASO 1: Pre-whitening - XOR con la primera parte de la whitening key
                padded_plaintext = pad(plaintext, AES.block_size)
                pre_w_extended = pre_whitening * (len(padded_plaintext) // len(pre_whitening) + 1)
                pre_w_extended = pre_w_extended[:len(padded_plaintext)]
                whitened_plaintext = bytes(a ^ b for a, b in zip(padded_plaintext, pre_w_extended))
                
                # PASO 2: Cifrado CBC estándar
                cipher = AES.new(key, AES.MODE_CBC)
                iv = cipher.iv  # Guardar el IV
                intermediate = cipher.encrypt(whitened_plaintext)
                
                # PASO 3: Post-whitening - XOR con la segunda parte de la whitening key
                post_w_extended = post_whitening * (len(intermediate) // len(post_whitening) + 1)
                post_w_extended = post_w_extended[:len(intermediate)]
                ct_bytes = bytes(a ^ b for a, b in zip(intermediate, post_w_extended))
                
                # Codificar y formar el JSON
                iv_b64 = b64encode(iv).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({'iv': iv_b64, 'ciphertext': ct, 'whitening': True})
                
                # Enviar mensaje con whitening
                msg = result.encode('utf-8')
                print("sent whitened-CBC message")
                client.send_bytes(msg)
                
                if not chat_active:
                    break
                
                # RECIBIR Y DESCIFRAR
                response = client.receive_bytes()
                json_input = response.decode(FORMAT)
                
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    iv = b64decode(b64['iv'])
                    
                    # PASO 1: Invertir post-whitening
                    post_w_extended = post_whitening * (len(ct) // len(post_whitening) + 1)
                    post_w_extended = post_w_extended[:len(ct)]
                    intermediate_dec = bytes(a ^ b for a, b in zip(ct, post_w_extended))
                    
                    # PASO 2: Descifrado CBC estándar
                    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                    whitened_plaintext_dec = cipher.decrypt(intermediate_dec)
                    
                    # PASO 3: Invertir pre-whitening
                    pre_w_extended = pre_whitening * (len(whitened_plaintext_dec) // len(pre_whitening) + 1)
                    pre_w_extended = pre_w_extended[:len(whitened_plaintext_dec)]
                    plaintext_padded = bytes(a ^ b for a, b in zip(whitened_plaintext_dec, pre_w_extended))
                    
                    # Quitar padding
                    pt = unpad(plaintext_padded, AES.block_size)
                    
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError) as e:
                    print(f"Incorrect whitening CBC decryption: {e}")
            else: # CTR
                # Convertir entrada a bytes
                plaintext = user_input.encode(FORMAT)
                
                # PASO 1: Pre-whitening - XOR con la primera parte de la whitening key
                # CTR no requiere padding, así que aplicamos XOR directamente
                pre_w_extended = pre_whitening * (len(plaintext) // len(pre_whitening) + 1)
                pre_w_extended = pre_w_extended[:len(plaintext)]
                # Aplicar XOR byte a byte
                whitened_plaintext = bytes(a ^ b for a, b in zip(plaintext, pre_w_extended))
                
                # PASO 2: Cifrado CTR estándar
                cipher = AES.new(key, AES.MODE_CTR)
                nonce = cipher.nonce  # Guardar el nonce
                intermediate = cipher.encrypt(whitened_plaintext)
                
                # PASO 3: Post-whitening - XOR con la segunda parte de la whitening key
                post_w_extended = post_whitening * (len(intermediate) // len(post_whitening) + 1)
                post_w_extended = post_w_extended[:len(intermediate)]
                ct_bytes = bytes(a ^ b for a, b in zip(intermediate, post_w_extended))
                
                # Codificar y formar el JSON
                nonce_b64 = b64encode(nonce).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = json.dumps({
                    'nonce': nonce_b64, 
                    'ciphertext': ct, 
                    'whitening': True
                })
                
                # Enviar mensaje con whitening
                msg = result.encode('utf-8')
                print("sent whitened-CTR message")
                client.send_bytes(msg)
                
                if not chat_active:
                    break
                
                # RECIBIR Y DESCIFRAR
                response = client.receive_bytes()
                json_input = response.decode(FORMAT)
                
                try:
                    b64 = json.loads(json_input)
                    ct = b64decode(b64['ciphertext'])
                    nonce = b64decode(b64['nonce'])
                    
                    # PASO 1: Invertir post-whitening
                    post_w_extended = post_whitening * (len(ct) // len(post_whitening) + 1)
                    post_w_extended = post_w_extended[:len(ct)]
                    intermediate_dec = bytes(a ^ b for a, b in zip(ct, post_w_extended))
                    
                    # PASO 2: Descifrado CTR estándar
                    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                    whitened_plaintext_dec = cipher.decrypt(intermediate_dec)
                    
                    # PASO 3: Invertir pre-whitening
                    pre_w_extended = pre_whitening * (len(whitened_plaintext_dec) // len(pre_whitening) + 1)
                    pre_w_extended = pre_w_extended[:len(whitened_plaintext_dec)]
                    pt = bytes(a ^ b for a, b in zip(whitened_plaintext_dec, pre_w_extended))
                    
                    # CTR no usa padding, así que no necesitamos unpad()
                    print("The message was: ", pt.decode(FORMAT))
                except (ValueError, KeyError) as e:
                    print(f"Incorrect whitening CTR decryption: {e}")
                
                    
                
            

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
    if not key:
        print("Failed to receive key from Google Drive")
        return None
    
    print(f"Received block cipher key: {key.hex()}")
    client.send("KEY RECEIVED")
    aes_prompt = client.receive()
    if not aes_prompt:
        print("No response from server after sending key received confirmation")
        return None
    print(aes_prompt)
    valid = False
    while not valid: 
        try:
            aes_mode = int(input(aes_prompt))
            if aes_mode == 1:
                mode = "ECB"
                valid = True
            elif aes_mode == 2:
                mode = "CBC"
                valid = True
            elif aes_mode == 3:
                mode = "CTR"
                valid = True
            else:
                print("Modo inválido")
        except ValueError:
            print("Selecciona un número")
    send_mode = (f"AES_MODE:{mode}")
    client.send(send_mode)
    response = client.receive()
    while True:
        choice_security = input(response)
        if choice_security == "1":
            break
        elif choice_security == "2":
            break
        elif choice_security == "3":
            break
        elif choice_security == "4":
            break
        else:
            print("Invalid input")
    client.send(choice_security)
    encrypted_chat2(client, mode, key, choice_security)
    
    
        
    
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