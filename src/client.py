from spake2_plus import SPAKE2_Plus_A
import nacl.secret

import socket

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 8000  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    shared_key = b'server_key'
    psw = input('Enter your password, correct password is \'hello_world\'\n')
    # psw = 'hello_world'

    client = SPAKE2_Plus_A(shared_key, psw.encode(encoding='utf-8'))
    msg_1 = client.start()
    s.connect((HOST, PORT))
    s.sendall(msg_1)

    data = s.recv(1024)
    key = client.finish(data)

    box = nacl.secret.SecretBox(key)
    msg = input("Enter a message to send\n")
    s.send(box.encrypt(msg.encode('utf-8')))

    msg = s.recv(1024)
    try:
        decrypted_msg = box.decrypt(msg).decode()
    except nacl.exceptions.ValueError:
        print("Invalid password")
    else:
        print(decrypted_msg)

