"""Вспомогательные функции участника bob. Шаги протокола — в bob.py."""
import argparse
import hashlib
import json
import math
import secrets
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent


def load_p():
    # Заранее выбранное простое p из RFC 3526, группа 14.
    data = json.loads((BASE / 'parameters.json').read_text(encoding='utf-8'))
    p = int(data['p'], 16)
    if p.bit_length() != 2048 or p % 2 == 0:
        raise ValueError('Восстановите исходный parameters.json с простым p')
    return p


def settings(role):
    parser = argparse.ArgumentParser(description=f'Протокол Шамира: {role}')
    parser.add_argument('--config', type=Path, default=BASE / f'{role}.json')
    path = parser.parse_args().config.resolve()
    config = json.loads(path.read_text(encoding='utf-8'))
    if not 1 <= config['port'] <= 65535 or config['timeout'] <= 0:
        raise ValueError('Порт должен быть 1–65535, тайм-аут — больше нуля')
    # Относительный каталог считается от файла настроек, а не от терминала.
    return config, path.parent / config['directory']


def make_exponents(p):
    while True:
        c = secrets.randbelow(p - 3) + 2
        if math.gcd(c, p - 1) == 1:
            return c, pow(c, -1, p - 1)


def key_to_number(key):
    if len(key) != 32:
        raise ValueError('Ключ должен содержать ровно 32 байта')
    return int.from_bytes(key, 'big') + 1  # m != 0 даже для нулевого ключа.


def number_to_key(number):
    if not 1 <= number <= 2 ** 256:
        raise ValueError('Не удалось восстановить 256-битный ключ')
    return (number - 1).to_bytes(32, 'big')  # Сохраняем ведущие нули.


def prepare(directory, p):
    directory.mkdir(parents=True, exist_ok=True)
    name = datetime.now().strftime('%Y%m%d_%H%M%S_') + secrets.token_hex(3)
    c, d = make_exponents(p)
    private = {'c': hex(c), 'd': hex(d)}
    (directory / f'private_{name}.json').write_text(json.dumps(private, indent=2), encoding='utf-8')
    return c, d, directory / f'key_{name}.key', directory / f'exchange_{name}.jsonl'


def record(log, direction, data):
    row = {'time': datetime.now().isoformat(timespec='seconds'), 'direction': direction, 'data': data}
    log.write(json.dumps(row, ensure_ascii=False) + '\n')
    log.flush()


def send_number(sock, number, log, label):
    text = format(number, 'x') + '\n'
    record(log, 'OUT', text)
    sock.sendall(text.encode('ascii'))
    print(f'{label} отправлено: {text.strip()}', flush=True)


def receive_number(sock, p, log, label):
    # TCP — поток байтов; одно число заканчивается переводом строки.
    data = bytearray()
    try:
        while not data.endswith(b'\n'):
            chunk = sock.recv(1)
            if not chunk:
                raise ConnectionError('Другой участник закрыл соединение')
            data.extend(chunk)
            if len(data) > 513:  # 512 hex-цифр для 2048 бит и перевод строки.
                raise ValueError('Слишком длинное число')
    except (OSError, ValueError):
        record(log, 'IN_PARTIAL', data.decode('ascii', errors='backslashreplace'))
        raise
    record(log, 'IN', data.decode('ascii', errors='backslashreplace'))
    digits = data[:-1]
    if not digits or any(ch not in b'0123456789abcdefABCDEF' for ch in digits):
        raise ValueError('Ожидалось шестнадцатеричное число')
    value = int(digits, 16)
    if not 1 <= value < p:
        raise ValueError('Полученное число вне диапазона от 1 до p-1')
    print(f'{label} получено: {digits.decode("ascii")}', flush=True)
    return value


def save_key(key_path, key):
    key_path.write_bytes(key)
    print(f'Ключ сохранён: {key_path} (32 байта = 256 бит)')
    print(f'SHA-256: {hashlib.sha256(key).hexdigest()}', flush=True)
