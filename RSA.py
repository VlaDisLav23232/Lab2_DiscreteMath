import hashlib
import random
import math

def is_prime(n: int):
    if n < 2: return False
    for i in range(2, math.ceil(math.sqrt(n))):
        # алгоритм евкліда, перебір до кореня з н;
        if n % i == 0:
            return False
    return True

def generate_prime(start=2**5, end=2**10):
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p

def modinv(a, m):
    """
    розширений алгоритм евкліда:
    знаходить таке x1, що
    x1 * a = 1 mod m
    """
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0


def generate_keys():
    # два різних простих числа
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()

    # добуток
    n = p * q

    # функція Ейлера для простих чисел
    phi = (p - 1) * (q - 1)

    # відкрита експонента
    e = 65537

    # modinv - обернене число
    d = modinv(e, phi)
    return (e, d, n)



def encrypt(msg: str, e, n):
    return [pow(ord(c), e, n) for c in msg]

def decrypt(cipher: list, d, n):
    return ''.join([chr(pow(c, d, n)) for c in cipher])

def hash_message(msg: str):
    return hashlib.sha256(msg.encode()).hexdigest()
