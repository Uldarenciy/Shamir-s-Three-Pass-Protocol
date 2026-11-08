"""Боб принимает ключ Алисы. Сначала запустите этот файл."""
import socket
from protocol import (load_p, settings, prepare, number_to_key,
                      send_number, receive_number, save_key)


def main():
    config, directory = settings('bob')
    p = load_p()
    c_b, d_b, key_path, log_path = prepare(directory, p)
    with socket.socket() as server, log_path.open('w', encoding='utf-8') as log:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((config['host'], config['port']))
        server.listen(1)
        print(f"Ожидание Алисы на {config['host']}:{config['port']}", flush=True)
        sock, _ = server.accept()
        with sock:
            sock.settimeout(config['timeout'])
            x1 = receive_number(sock, p, log, 'x1')  # 1. Преобразование Алисы.
            x2 = pow(x1, c_b, p)                    # 2. Добавляем преобразование Боба.
            send_number(sock, x2, log, 'x2')
            x3 = receive_number(sock, p, log, 'x3')  # 3. Алиса сняла своё преобразование.
            m = pow(x3, d_b, p)                     # Снимаем преобразование Боба локально.
            key = number_to_key(m)
    save_key(key_path, key)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nОбмен остановлен')
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f'Ошибка: {error}')
