"""CLIENT"""

import socket
import threading
import json
from RSA import generate_keys, encrypt, decrypt, hash_message

class Client:
    """A client for a chat-program"""
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        """Initialize the connection to the server"""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.server_ip, self.port))

        self.s.send(self.username.encode())

        # create key pairs
        print("[client]: Generating RSA keys...")
        self.e, self.d, self.n = generate_keys()

        # exchange public keys - sending client's public key to server
        public_key = {'e': self.e, 'n': self.n}
        print("[client]: Sending my public key to server...")
        self.s.send(json.dumps(public_key).encode())

        # receive server's public key
        print("[client]: Receiving server's public key...")
        server_public_key_data = self.s.recv(1024).decode()
        server_public_key = json.loads(server_public_key_data)
        self.server_e = server_public_key['e']
        self.server_n = server_public_key['n']

        print("[client]: RSA key exchange completed")

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        """Handle incoming messages from the server"""
        while True:
            try:
                data = self.s.recv(4096).decode()
                if not data:
                    break

                message_data = json.loads(data)
                received_hash = message_data['hash']
                encrypted_message = message_data['message']

                # Convert string representation of list back to actual list of integers
                encrypted_message = [int(x) for x in encrypted_message]

                # decrypt message with the private key
                decrypted_message = decrypt(encrypted_message, self.d, self.n)

                # verify message integrity
                calculated_hash = hash_message(decrypted_message)
                if calculated_hash != received_hash:
                    print("[client]: Message integrity check\
 failed! Message may have been tampered with.")
                    continue

                print(f"\n{decrypted_message}")
            except Exception as e:
                print(f"[client]: Error receiving message: {e}")
                break

    def write_handler(self):
        """Handle sending messages to the server"""
        while True:
            message = input()
            if not message:
                continue

            try:
                # calculate message hash for integrity check
                message_hash = hash_message(message)

                # encrypt message with the server's public key
                encrypted_message = encrypt(message, self.server_e, self.server_n)

                # Convert list of integers to strings for JSON serialization
                encrypted_message_str = [str(x) for x in encrypted_message]

                # send message as (hash, encrypted_message)
                message_data = {
                    'hash': message_hash,
                    'message': encrypted_message_str
                }
                self.s.send(json.dumps(message_data).encode())
            except Exception as e:
                print(f"[client]: Error sending message: {e}")
                break

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
