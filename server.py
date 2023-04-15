from src.spake2 import SPAKE2_B

import socket
import nacl.secret
 
HOST = "127.0.0.1"
PORT = 8000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        
        server = SPAKE2_B(b"password")
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




