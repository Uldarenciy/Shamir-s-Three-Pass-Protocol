"""Математика, три прохода Шамира и журналирование для alice."""
import argparse
import hashlib
import os
import select
import sys
import json
import math
import secrets
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

BASE = Path(__file__).resolve().parent


def load_p(): # загрузка p
    data = json.loads((BASE / 'parameters.json').read_text(encoding='utf-8'))
    p = int(data['p'], 16)
    if p.bit_length() != 2048 or p % 2 == 0:
        raise ValueError('Восстановите исходный parameters.json с простым p')
    return p


def settings(role): # файл для участинка и данные конфига(порт и т.д.)
    parser = argparse.ArgumentParser(description=f'Протокол Шамира: {role}')
    parser.add_argument('--config', type=Path, default=BASE / f'{role}.json')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--initiate', dest='initiate', action='store_true', help='создать и передать K')
    mode.add_argument('--receive-key', dest='initiate', action='store_false', help='принять K')
    parser.set_defaults(initiate=(role == 'alice'))
    args = parser.parse_args()
    path = args.config.resolve()
    config = json.loads(path.read_text(encoding='utf-8'))
    if not 1 <= config['port'] <= 65535 or config['timeout'] <= 0:
        raise ValueError('Порт должен быть 1–65535, тайм-аут — больше нуля')
    config['initiate'] = args.initiate
    return config, path.parent / config['directory']


def make_exponents(p): # вычисляем обратное число, если НОД = 1 нашли
    while True:
        a = secrets.randbelow(p - 3) + 2
        if math.gcd(a, p - 1) == 1:
            d_A = pow(a, -1, p - 1)
            return a, d_A


def prepare(directory, p): # параметры a, d_A
    directory.mkdir(parents=True, exist_ok=True)
    name = datetime.now().strftime('%Y%m%d_%H%M%S_') + secrets.token_hex(3)
    a, d_A = make_exponents(p)
    private = {'a': hex(a), 'd_A': hex(d_A)}
    (directory / f'private_{name}.json').write_text(json.dumps(private, indent=2), encoding='utf-8')
    return a, d_A, directory / f'key_{name}.key', directory / f'exchange_{name}.jsonl'


def record(log, direction, data):
    row = {'time': datetime.now().isoformat(timespec='seconds'), 'direction': direction, 'data': data}
    log.write(json.dumps(row, ensure_ascii=False) + '\n')
    log.flush()


def send_line(sock, text, log):
    text += '\n'
    record(log, 'OUT', text)
    sock.sendall(text.encode('ascii'))


def receive_line(sock, log, limit=513):
    data = bytearray()
    try:
        while not data.endswith(b'\n'):
            chunk = sock.recv(1)
            if not chunk:
                raise ConnectionError('Собеседник закрыл соединение')
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError('Слишком длинное сообщение')
    except (OSError, ValueError):
        record(log, 'IN_PARTIAL', data.decode('ascii', errors='backslashreplace'))
        raise
    record(log, 'IN', data.decode('ascii', errors='backslashreplace'))
    return data.decode('ascii').strip()


def send_number(sock, number, log):
    send_line(sock, format(number, 'x'), log)


def receive_number(sock, p, log):
    value = int(receive_line(sock, log), 16)
    if not 1 <= value < p:
        raise ValueError('Полученное число вне диапазона от 1 до p-1')
    return value


def exchange_key(sock, p, a, d_A, log, initiate):
    # Оба сообщают роль: ровно одна сторона должна создавать K.
    mode = 'INITIATE' if initiate else 'RECEIVE'
    send_line(sock, mode, log)
    peer = receive_line(sock, log, 16)
    if peer not in ('INITIATE', 'RECEIVE') or peer == mode:
        raise ValueError('Нужен ровно один инициатор: --initiate и --receive-key')
    if initiate:
        K = secrets.token_bytes(32)
        m = int.from_bytes(K, 'big') + 1
        x1 = pow(m, a, p)
        send_number(sock, x1, log)              # 1. Преобразование инициатора.
        x2 = receive_number(sock, p, log)      # 2. Получатель добавил своё.
        x3 = pow(x2, d_A, p)
        send_number(sock, x3, log)             # 3. Инициатор снял своё.
    else:
        x1 = receive_number(sock, p, log)
        x2 = pow(x1, a, p)
        send_number(sock, x2, log)
        x3 = receive_number(sock, p, log)
        m = pow(x3, d_A, p)                # 4. Получатель снимает своё локально.
        if not 1 <= m <= 2 ** 256:
            raise ValueError('Не удалось восстановить сеансовый ключ')
        K = (m - 1).to_bytes(32, 'big')
    return K


def save_key(key_path, K):
    key_path.write_bytes(K)
    print(f'Ключ 256 бит сохранён: {key_path}', flush=True)
    print(f'SHA-256: {hashlib.sha256(K).hexdigest()}', flush=True)


def chat(sock, K, log, role):
    cipher = AESGCM(K)
    prefix = b'A' if role == 'alice' else b'B'
    peer_prefix = b'B' if role == 'alice' else b'A'
    sent = received = 0
    pending = b''
    sock.settimeout(None)
    print('Чат готов. Писать можно в любой момент; /exit — выход.', flush=True)
    print('Вы: ', end='', flush=True)
    while True:
        ready, _, _ = select.select([sock, sys.stdin], [], [])
        if sock in ready:
            packet = bytes.fromhex(receive_line(sock, log, 2 * (65536 + 28) + 1))
            # Направление и счётчик исключают повтор nonce с одним ключом.
            nonce = peer_prefix + received.to_bytes(11, 'big')
            if packet[:12] != nonce:
                raise ValueError('Неверный номер сообщения')
            try:
                text = cipher.decrypt(nonce, packet[12:], None).decode('utf-8')
            except InvalidTag:
                raise ValueError('Сообщение повреждено или ключи не совпадают') from None
            received += 1
            if text == '/exit':
                print('\nСобеседник завершил чат', flush=True)
                return
            print('\nСобеседник: ' + text + '\nВы: ', end='', flush=True)
        if sys.stdin in ready:
            # Читаем байты, чтобы вставка нескольких строк не застревала в буфере stdin.
            pending += os.read(sys.stdin.fileno(), 4096) or b'\n/exit\n'
            while b'\n' in pending:
                data, pending = pending.split(b'\n', 1)
                text = data.decode('utf-8').rstrip('\r')
                if not text:
                    continue
                if len(data) > 65536:
                    print('Фраза слишком длинная: максимум 64 КиБ.', flush=True)
                    continue
                nonce = prefix + sent.to_bytes(11, 'big')
                packet = nonce + cipher.encrypt(nonce, text.encode('utf-8'), None)
                send_line(sock, packet.hex(), log)
                sent += 1
                if text == '/exit':
                    print('Чат завершён', flush=True)
                    return
                print('Вы: ', end='', flush=True)
            if len(pending) > 65536:
                raise ValueError('Фраза слишком длинная: максимум 64 КиБ')
