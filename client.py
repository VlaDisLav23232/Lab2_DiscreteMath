"""CLIENT"""

import socket
import threading
import json

import sys
# reader() працює в окремому потоці
# і вихід з нього не завершує програму

from RSA import generate_keys, encrypt, decrypt, hash_message

class Client:
    """Клієнт для шифрованого чату з використанням RSA шифрування"""

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        """
        Ініціалізація клієнта
        
        Args:
            server_ip: IP-адреса сервера
            port: Порт для підключення
            username: Ім'я користувача в чаті
        """
        self.server_ip=server_ip
        self.port = port
        self.username = username
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def initialize(self):
        """
        З'єднання з сервером, обмін ключами та запуск потоків читання і запису
        """
        self.s.connect((self.server_ip, self.port))
        self.s.send(self.username.encode())

        self.public_key, self.private_key = generate_keys()
        srv_key_raw = self.s.recv(8192).decode()
        self.server_key = json.loads(srv_key_raw.split(": ", 1)[1])
        self.s.send(f"KEY: {json.dumps(self.public_key)}".encode())
        print("[client]: keys exchanged")

        threading.Thread(target=self.reader, daemon=True).start()
        self.writer()

    def reader(self):
        """
        Функція для отримання та розшифрування повідомлень від сервера.
        Запускається в окремому потоці.
        """
        while True:
            raw = self.s.recv(1024)
            # очікування повідомлення
            if not raw:
                print("[client]: server closed connection")
                sys.exit(0)
            try:
                obj = json.loads(raw.decode())
                text = decrypt(obj["m"], self.private_key)
                if hash_message(text) != obj["h"]:
                    print("[Warning]: message integrity check failed.")
                    continue
                print(text)
            except Exception as e:
                print(f"[client]: error: {e}")

    def writer(self):
        """
        Функція для шифрування та відправки повідомлень на сервер.
        Працює в основному потоці.
        
        В циклі отримує повідомлення,
        обчислює хеш,
        шифрує повідомлення,
        відправляє json
        """
        while True:
            try:
                msg = input()
                h = hash_message(msg)
                cipher = encrypt(msg, self.server_key).decode()
                self.s.send(json.dumps({"h": h, "m": cipher}).encode())
            except (EOFError, KeyboardInterrupt):
                # обробляє Ctrl C
                self.s.close()
                break

if __name__ == "__main__":
    Client("127.0.0.1", 9001, input("Ваш нік: ").strip()).initialize()
