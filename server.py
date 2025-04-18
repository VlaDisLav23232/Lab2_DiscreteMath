import socket
import threading
import json
from RSA import generate_keys, encrypt, decrypt, hash_message

class Server:
    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.lookup = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        self.public_key, self.private_key = generate_keys()
        print("[server]: keys generated")

        while True:
            c, _ = self.s.accept()
            username = c.recv(1024).decode().strip()
            print(f"{username} tries to connect")

            # обмін публічними ключами
            c.send(f"KEY: {json.dumps(self.public_key)}".encode())
            client_pub = json.loads(c.recv(8192).decode().split(": ", 1)[1])
            self.lookup[c] = (username, tuple(client_pub))
            self.clients.append(c)

            self.broadcast(f"** {username} joined **", exclude=None)
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def broadcast(self, plaintext: str, exclude: socket.socket | None):
        for cli in self.clients:
            if cli is exclude:
                continue
            h = hash_message(plaintext)
            cipher = encrypt(plaintext, self.lookup[cli][1]).decode()
            cli.send(json.dumps({"h": h, "m": cipher}).encode())

    def handle(self, client: socket.socket):
        username = self.lookup[client][0]
        try:
            while True:
                raw = client.recv(1024)
                if not raw:
                    break
                try:
                    obj = json.loads(raw.decode())
                    msg_plain = decrypt(obj["m"], self.private_key)
                    if hash_message(msg_plain) != obj["h"]:
                        print("[server]: integrity fail, message dropped")
                        continue
                    self.broadcast(f"{username}: {msg_plain}", exclude=client)
                except Exception as e:
                    print(f"[server]: error decoding message: {e}")
        finally:
            print(f"{username} disconnected")
            self.clients.remove(client)
            self.broadcast(f"** {username} left **", exclude=None)
            client.close()

if __name__ == "__main__":
    Server(9001).start()
