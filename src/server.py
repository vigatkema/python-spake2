from spake2_plus import SPAKE2_Plus_B

import socket
import nacl.secret
 
HOST = "127.0.0.1"
PORT = 8000

shared_key = b'server_key'
client_key = b'hello_world'
pwd_verifier = SPAKE2_Plus_B._convert_pass_to_encoding(client_key)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        
        server = SPAKE2_Plus_B(shared_key, pwd_verifier)
        msg_2 = server.start()

        data = conn.recv(1024)
        key = server.finish(data)
        box = nacl.secret.SecretBox(key)

        conn.sendall(msg_2)
        
        msg = conn.recv(1024)

        try:
            decrypted_msg = box.decrypt(msg).decode('utf-8')
        except nacl.exceptions.CryptoError:
            print("Invalid key, closing connection")
            conn.close()
        else:
            print(decrypted_msg)
            response_msg = f"Received: {decrypted_msg}"
            print(response_msg)
            response = box.encrypt(response_msg.encode('utf-8'))

            conn.sendall(response)
            print("Successful communication")




