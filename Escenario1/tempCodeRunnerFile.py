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
                
                