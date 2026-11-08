"""Алиса создаёт 256-битный ключ и передаёт его Бобу за три прохода."""
import secrets
import socket
from protocol import (load_p, settings, prepare, key_to_number,
                      send_number, receive_number, save_key, chat)


def main():
    config, directory = settings('alice')
    p = load_p()
    c_a, d_a, key_path, log_path = prepare(directory, p)
    key = secrets.token_bytes(32)
    m = key_to_number(key)
    with log_path.open('w', encoding='utf-8') as log:
        with socket.create_connection((config['host'], config['port']), timeout=config['timeout']) as sock:
            x1 = pow(m, c_a, p)                     # 1. Преобразование Алисы.
            send_number(sock, x1, log, 'x1')
            x2 = receive_number(sock, p, log, 'x2')  # 2. Боб добавил своё преобразование.
            x3 = pow(x2, d_a, p)                    # 3. Снимаем преобразование Алисы.
            send_number(sock, x3, log, 'x3')
            save_key(key_path, key)
            chat(sock, p, c_a, d_a, log, first=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nОбмен остановлен')
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f'Ошибка: {error}')
