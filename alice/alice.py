"""Алиса передаёт или принимает сеансовый ключ по Шамиру, затем начинается AES-чат."""
import socket
from protocol import load_p, settings, prepare, chat, exchange_key, save_key


def main():
    config, directory = settings('alice')
    p = load_p()
    a, d_A, key_path, log_path = prepare(directory, p)
    with log_path.open('w', encoding='utf-8') as log:
        with socket.create_connection((config['host'], config['port']), timeout=config['timeout']) as sock:
            K = exchange_key(sock, p, a, d_A, log, config['initiate'])
            save_key(key_path, K)
            chat(sock, K, log, 'alice')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nОбмен остановлен')
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f'Ошибка: {error}')
