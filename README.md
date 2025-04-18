# Lab2_DiscreteMath

**Команда:**  
Дзьобан Максим, Шимановський Владислав

**Розподіл роботи:**  
- **Дзьобан Максим**: `Server.py`, `RSA.py`, `README.md`  
- **Шимановський Владислав**: `Client.py`, `README.md`


Розроблено алгоритм RSA обміну ключами та відповідне кодування повідомлень цими ключами.

Імплементовано **message integrity**, відповідно до якого обмін повідомленнями відбувається так:
1. Порахувати хеш повідомлення
2. Закодувати повідомлення
3. Надіслати у вигляді: `(hash, encrypted_message)`
4. Розкодувати повідомлення
5. Перевірити, чи обчислений хеш співпадає з отриманим

---

## Алгоритм RSA

### 1. Генерація ключів (`generate_keys`)
- Генеруються два прості числа `p`, `q`
- Обчислюється `n = p * q`
- Фіксується `e = 65537`
- Обчислюється `d`, що є оберненим до `e` за модулем φ(n)

### 2. Шифрування (`encrypt`)
- Кожен символ підноситься до `e` за модулем `n`, отримуємо `c`
- Масив `c` кодується у JSON + HEX

### 3. Дешифрування (`decrypt`)
- Декодуємо HEX → JSON
- Кожне число `c` дешифрується як `m = c^d mod n`

### 4. Хешування (`hash_message`)
- Додається SHA-256 до кожного повідомлення
- Це дозволяє виявити зміну повідомлення під час передачі

---

## Логіка роботи

### Сервер
- Генерує ключі
- Приймає сокети
- Відправляє свій public key
- Отримує public key клієнта
- Додає клієнта до `lookup`
- Обробляє повідомлення: розшифровує, перевіряє хеш, пересилає іншим клієнтам

### Клієнт
- З’єднується із сервером
- Отримує публічний ключ сервера
- Надсилає свій public key
- Запускає два потоки: `reader` (recv) та `writer` (input + send)

---

## Запуск

```bash
python3 server.py
# у новому терміналі:
python3 client.py
```


![Usage](screenshot.png)
