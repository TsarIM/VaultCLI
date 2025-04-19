# client.py
import argparse
import socket
import json
import os
import sys
import hashlib
import secrets
import hmac
import binascii
from Crypto.Cipher import AES  # type: ignore
from Crypto.Util.Padding import pad, unpad  # type: ignore
import reed_solomon

# Constants
METADATA_SERVER_HOST = '127.0.0.1'
METADATA_SERVER_PORT = 8000
DATA_SERVER_BASE_PORT = 8100
DATA_SERVER_COUNT = 14
NUM_DATA_CHUNKS = 10
NUM_PARITY_CHUNKS = 4
CHUNK_SIZE = 1024 * 1024  # 1MB


def connect_to_metadata_server():
    servers = [
        (METADATA_SERVER_HOST, METADATA_SERVER_PORT),       # Primary
        (METADATA_SERVER_HOST, METADATA_SERVER_PORT + 1)    # Backup
    ]
    for host, port in servers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            return s
        except:
            continue
    print("Error: Could not connect to any metadata server.")
    sys.exit(1)


def send_request_to_metadata_server(request):
    try:
        s = connect_to_metadata_server()
        s.sendall(json.dumps(request).encode('utf-8'))
        response = s.recv(8192).decode('utf-8')
        s.close()
        return json.loads(response)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def get_servers_status():
    server_status = []
    for i in range(DATA_SERVER_COUNT):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(('127.0.0.1', DATA_SERVER_BASE_PORT + i))
            s.close()
            server_status.append(True)
        except:
            server_status.append(False)
    return server_status


def derive_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 100000)


def compute_hmac(key, data):
    h = hmac.new(key, data, hashlib.sha256)
    return h.hexdigest()


def verify_hmac(key, data, hmac_val):
    computed = compute_hmac(key, data)
    return hmac.compare_digest(computed, hmac_val)


def upload_chunk(server_id, user_id, chunk_id, chunk_data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', DATA_SERVER_BASE_PORT + server_id))
        s.sendall('U'.encode('utf-8'))
        header = {'user_id': user_id, 'chunk_id': chunk_id}
        header_data = json.dumps(header).encode('utf-8')
        s.sendall(len(header_data).to_bytes(4, byteorder='big'))
        s.sendall(header_data)
        s.sendall(len(chunk_data).to_bytes(4, byteorder='big'))
        s.sendall(chunk_data)
        response = s.recv(1024).decode('utf-8')
        s.close()
        return json.loads(response).get('status') == 'success'
    except Exception as e:
        print(f"Error uploading chunk to server {server_id}: {e}")
        return False


def download_chunk(server_id, user_id, chunk_id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', DATA_SERVER_BASE_PORT + server_id))
        s.sendall('D'.encode('utf-8'))
        header = {'user_id': user_id, 'chunk_id': chunk_id}
        header_data = json.dumps(header).encode('utf-8')
        s.sendall(len(header_data).to_bytes(4, byteorder='big'))
        s.sendall(header_data)
        chunk_size_bytes = s.recv(4)
        if not chunk_size_bytes or len(chunk_size_bytes) != 4:
            s.close()
            return None
        chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big')
        chunk_data = b''
        remaining = chunk_size
        while remaining > 0:
            data = s.recv(min(4096, remaining))
            if not data:
                break
            chunk_data += data
            remaining -= len(data)
        s.close()
        return chunk_data
    except Exception as e:
        print(f"Error downloading chunk from server {server_id}: {e}")
        return None


def delete_chunk(server_id, user_id, chunk_id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', DATA_SERVER_BASE_PORT + server_id))
        s.sendall('X'.encode('utf-8'))
        header = {'user_id': user_id, 'chunk_id': chunk_id}
        header_data = json.dumps(header).encode('utf-8')
        s.sendall(len(header_data).to_bytes(4, byteorder='big'))
        s.sendall(header_data)
        response = s.recv(1024).decode('utf-8')
        s.close()
        return json.loads(response).get('status') == 'success'
    except Exception as e:
        print(f"Error deleting chunk from server {server_id}: {e}")
        return False


def register(user_id, password):
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    request = {'action': 'register', 'user_id': user_id, 'password_hash': password_hash, 'salt': salt}
    response = send_request_to_metadata_server(request)
    if response.get('status') == 'success':
        print(f"User {user_id} registered successfully.")
        server_status = get_servers_status()
        for i in range(DATA_SERVER_COUNT):
            if server_status[i]:
                upload_chunk(i, user_id, 'init', b'')
    else:
        print(f"Registration failed: {response.get('message')}")


def authenticate(user_id, password):
    request = {'action': 'get_salt', 'user_id': user_id}
    response = send_request_to_metadata_server(request)
    if response.get('status') != 'success':
        print(f"Authentication failed: {response.get('message')}")
        return None
    salt = response.get('salt')
    password_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    request = {'action': 'authenticate', 'user_id': user_id, 'password_hash': password_hash}
    response = send_request_to_metadata_server(request)
    return salt if response.get('status') == 'success' else None


def upload_file(file_path, user_id, password):
    salt = authenticate(user_id, password)
    if not salt:
        return
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    with open(file_path, 'rb') as f:
        file_data = f.read()
    filename = os.path.basename(file_path)
    server_status = get_servers_status()
    available_servers = sum(server_status)
    if available_servers < NUM_DATA_CHUNKS:
        print(f"Not enough servers. Need {NUM_DATA_CHUNKS}, available {available_servers}")
        return
    chunk_size = (len(file_data) + NUM_DATA_CHUNKS - 1) // NUM_DATA_CHUNKS
    padded_data = file_data + bytes([0] * (chunk_size * NUM_DATA_CHUNKS - len(file_data)))
    data_chunks = [bytearray(padded_data[i * chunk_size:(i + 1) * chunk_size]) for i in range(NUM_DATA_CHUNKS)]
    key = derive_key(password, salt)
    rs = reed_solomon.ReedSolomonCodec(NUM_DATA_CHUNKS, NUM_PARITY_CHUNKS)
    parity_chunks = rs.encode(data_chunks)
    all_chunks = data_chunks + parity_chunks
    chunk_metadata = []
    encrypted_chunks = []
    for i, chunk in enumerate(all_chunks):
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc = cipher.encrypt(pad(chunk, AES.block_size))
        hmac_val = compute_hmac(key, enc)
        chunk_metadata.append({'chunk_no': i, 'iv': binascii.hexlify(iv).decode(), 'hmac': hmac_val})
        encrypted_chunks.append(enc)
    request = {'action': 'store_metadata', 'user_id': user_id, 'filename': filename, 'chunk_data': chunk_metadata}
    response = send_request_to_metadata_server(request)
    if response.get('status') != 'success':
        print(f"Error storing metadata: {response.get('message')}")
        return
    chunk_ids = response.get('chunk_ids')
    for i in range(len(all_chunks)):
        if i < len(server_status) and server_status[i]:
            upload_chunk(i, user_id, chunk_ids[i], encrypted_chunks[i])


def list_files(user_id, password):
    if not authenticate(user_id, password):
        return
    request = {'action': 'list_files', 'user_id': user_id}
    response = send_request_to_metadata_server(request)
    if response.get('status') == 'success':
        for f in response.get('files', []):
            print(f"- {f}")
    else:
        print(f"Error: {response.get('message')}")


def download_file(filename, user_id, password):
    salt = authenticate(user_id, password)
    if not salt:
        return
    request = {'action': 'get_file_metadata', 'user_id': user_id, 'filename': filename}
    response = send_request_to_metadata_server(request)
    if response.get('status') != 'success':
        print(f"Error: {response.get('message')}")
        return
    metadata = response.get('metadata')
    server_status = get_servers_status()
    key = derive_key(password, salt)
    chunks, indices = [], []
    for i in range(NUM_DATA_CHUNKS + NUM_PARITY_CHUNKS):
        if len(chunks) >= NUM_DATA_CHUNKS:
            break
        if i < len(server_status) and server_status[i]:
            meta = next((m for m in metadata if m['chunk_no'] == i), None)
            if not meta:
                continue
            enc = download_chunk(i, user_id, meta['chunk_id'])
            if enc and verify_hmac(key, enc, meta['hmac']):
                iv = bytes.fromhex(meta['iv'])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                dec = unpad(cipher.decrypt(enc), AES.block_size)
                chunks.append(bytearray(dec))
                indices.append(i)
    if len(chunks) < NUM_DATA_CHUNKS:
        print("Insufficient chunks to reconstruct file.")
        return
    rs = reed_solomon.ReedSolomonCodec(NUM_DATA_CHUNKS, NUM_PARITY_CHUNKS)
    data_chunks = rs.decode(chunks, indices)
    with open(filename, 'wb') as f:
        f.write(b''.join(data_chunks))
    print(f"File {filename} downloaded successfully.")


def delete_file(filename, user_id, password):
    if not authenticate(user_id, password):
        return
    request = {'action': 'get_file_metadata', 'user_id': user_id, 'filename': filename}
    response = send_request_to_metadata_server(request)
    if response.get('status') != 'success':
        print(f"Error: {response.get('message')}")
        return
    metadata = response.get('metadata')
    for m in metadata:
        delete_chunk(m['chunk_no'], user_id, m['chunk_id'])
    request = {'action': 'delete_file', 'user_id': user_id, 'filename': filename}
    response = send_request_to_metadata_server(request)
    if response.get('status') == 'success':
        print(f"File {filename} deleted.")
    else:
        print(f"Error deleting file: {response.get('message')}")


def main():
    parser = argparse.ArgumentParser(description='Distributed Storage Client')
    subparsers = parser.add_subparsers(dest='command')

    register_parser = subparsers.add_parser('register')
    register_parser.add_argument('user_id')
    register_parser.add_argument('password')

    upload_parser = subparsers.add_parser('upload')
    upload_parser.add_argument('file_path')
    upload_parser.add_argument('user_id')
    upload_parser.add_argument('password')

    list_parser = subparsers.add_parser('list')
    list_parser.add_argument('user_id')
    list_parser.add_argument('password')

    download_parser = subparsers.add_parser('download')
    download_parser.add_argument('filename')
    download_parser.add_argument('user_id')
    download_parser.add_argument('password')

    delete_parser = subparsers.add_parser('delete')
    delete_parser.add_argument('filename')
    delete_parser.add_argument('user_id')
    delete_parser.add_argument('password')

    args = parser.parse_args()

    if args.command == 'register':
        register(args.user_id, args.password)
    elif args.command == 'upload':
        upload_file(args.file_path, args.user_id, args.password)
    elif args.command == 'list':
        list_files(args.user_id, args.password)
    elif args.command == 'download':
        download_file(args.filename, args.user_id, args.password)
    elif args.command == 'delete':
        delete_file(args.filename, args.user_id, args.password)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
