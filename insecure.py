from Crypto.Util.number import bytes_to_long, long_to_bytes
from secrets import token_bytes
import socket
from hashlib import shake_256
import argparse
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import threading

def send_thread(encryption_key: bytes, socket: socket.socket) -> None:
    aead = ChaCha20Poly1305(encryption_key)
    while not stop_threads.is_set():
        message = input().encode()
        nonce = token_bytes(12)
        ciphertext = aead.encrypt(nonce, message, None)
        packet = nonce + ciphertext
        socket.send(packet)
    socket.send(b'EXITED')
    print('Send thread stopped')

def recv_thread(encryption_key: bytes, socket: socket.socket) -> None:
    aead = ChaCha20Poly1305(encryption_key)
    while not stop_threads.is_set():
        packet = socket.recv(1024)
        if packet == b'EXITED': break
        nonce, ciphertext = packet[:12], packet[12:]
        message = aead.decrypt(nonce, ciphertext, None).decode()
        print(message)
    print('Recv thread stopped')

common_parser = argparse.ArgumentParser(add_help=False)
common_parser.add_argument('-z', '--password', help='shared password', type=str, required=True)
common_parser.add_argument('-s', '--size', help='size of random number: 1024, 2048, 3072. Default: 3072', type=int, default=3072, choices=[1024, 2048, 3072])

parser = argparse.ArgumentParser(description='SPAKE protol communication with ChaCha20-Poly1305 encryption')
subparsers = parser.add_subparsers(dest="mode", required=True)

server_parser = subparsers.add_parser('bind', parents=[common_parser], help='Run in server mode (listen)')
server_parser.add_argument('host', nargs='?', default='127.0.0.1', help='Address to bind the server. Default: 127.0.0.1')
server_parser.add_argument('port', nargs='?', type=int, default=8888, help='Port to bind to. Default: 8888')

client_parser = subparsers.add_parser('connect', parents=[common_parser], help='Run in client mode')
client_parser.add_argument('host', nargs='?', default='127.0.0.1', help='Host to connect to. Default: 127.0.0.1')
client_parser.add_argument('port', nargs='?', type=int, default=8888, help='Port to connect to. Default: 8888')

args = parser.parse_args()

server_status = args.mode == "bind"
stop_threads = threading.Event()
HOST=args.host
PORT=args.port
SHARED_PW=args.password.encode()
PARAMS_LEN=int(args.size/8)

random_bytes = token_bytes(PARAMS_LEN)
random_number = bytes_to_long(random_bytes)
shared_pw_as_number = bytes_to_long(SHARED_PW)
print(shared_pw_as_number)
product = long_to_bytes(random_number * shared_pw_as_number)
print(random_number * shared_pw_as_number)

if server_status:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print('Server started')

    client, addr = server.accept()
    print(f'Got connection from {addr}')
    client.send(product)

    recv_product = bytes_to_long(client.recv(1024))
else:
    try:
        client = socket.socket()
        client.connect((HOST, PORT))
        recv_product = bytes_to_long(client.recv(1024))
        client.send(product)
    except ConnectionRefusedError:
        print('Could not connect :(')
        exit()

shared_secret = long_to_bytes(recv_product * random_number)
encryption_key = shake_256(shared_secret).digest(32)
print('Secure communication established')

th_send = threading.Thread(target=send_thread, args=(encryption_key, client))
th_recv = threading.Thread(target=recv_thread, args=(encryption_key, client))

th_send.start()
th_recv.start()

try:
    while th_send.is_alive() or th_recv.is_alive():
        th_recv.join(timeout=0.1)
        th_send.join(timeout=0.1)
except KeyboardInterrupt:
    print('Stop initiated')
    stop_threads.set()
