"""RSA"""

import hashlib
import random
import math
import json

def is_prime(n: int) -> bool:
    """
    перевірка чи є простим числом 
    за домогою ітерації до кореня з числа n;
    """
    if n < 2:
        return False
    for i in range(2, int(math.isqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(start=2**10, end=2**15):
    """
    генеруємо велике просте число в range(2**10, 2**15)
    """
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p

def modinv(a, m):
    """
    обернений за модулем m елемент до a 
    за допомогою розширеного алгоритму Евкліда.
    знаходить таке x1, що
    x1 * a = 1 mod m
    """
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0

def generate_keys() -> tuple:
    """
    генерує RSA ключі - приватний і публічний
    """
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return ((n, e), (n, d))

def encrypt(message, public_key):
    """
    шифрує повідомлення з використанням RSA публічного ключа
    
    кожен символ у повідомленні перетворюється у число, 
    підноситься до степеня key за модулем n, після чого список
    чисел конвертується у стрінг, 
    кодується у байти та переводиться у hex-представлення
    """
    n, key = public_key
    arr = [pow(ord(char), key, n) for char in message]
    return bytes(str(arr), 'ascii').hex().encode()

def decrypt(encoded, private_key):
    """
    дешифрує повідомлення, зашифроване функцією 
    encrypt, з використанням приватного ключа
    """
    try:
        n, key = private_key
        if isinstance(encoded, bytes):
            encoded = encoded.decode()
        message_decoded = bytes.fromhex(encoded).decode()
        arr = json.loads(message_decoded)
        message_decrypted = ""
        text = [chr(pow(char, key, n)) for char in arr]
        return message_decrypted.join(text)
    except TypeError as e:
        raise e

def hash_message(message: str) -> str:
    """
    SHA-256 хеш
    """
    return hashlib.sha256(message.encode('utf-8')).hexdigest()
