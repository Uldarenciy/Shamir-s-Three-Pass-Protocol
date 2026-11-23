"""Боб передаёт или принимает сеансовый ключ по Шамиру, затем начинается AES-чат."""
import socket
from protocol import load_p, settings, prepare, chat, exchange_key, save_key


def main():
    config, directory = settings('bob')
    p = load_p()
    b, d_B, key_path, log_path = prepare(directory, p)
    with socket.socket() as server, log_path.open('w', encoding='utf-8') as log:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((config['host'], config['port']))
        server.listen(1)
        print(f"Ожидание Алисы на {config['host']}:{config['port']}", flush=True)
        sock, _ = server.accept()
        with sock:
            sock.settimeout(config['timeout'])
            K = exchange_key(sock, p, b, d_B, log, config['initiate'])
            save_key(key_path, K)
            chat(sock, K, log, 'bob')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nОбмен остановлен')
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f'Ошибка: {error}')
