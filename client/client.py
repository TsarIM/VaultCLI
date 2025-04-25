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

server_ips = [
    '127.0.0.1', '127.0.0.1', '127.0.0.1', '127.0.0.1',
    '127.0.0.1', '127.0.0.1', '127.0.0.1', '127.0.0.1',
    '127.0.0.1', '127.0.0.1', '127.0.0.1', '127.0.0.1',
    '127.0.0.1', '127.0.0.1'
]

METADATA_SERVER_HOST = '127.0.0.1'
METADATA_SERVER_PORT = 8000
DATA_SERVER_BASE_PORT = 8100
NUM_DATA_CHUNKS = 10
NUM_PARITY_CHUNKS = 4
TOTAL_SERVERS = NUM_DATA_CHUNKS + NUM_PARITY_CHUNKS


def connect_to_metadata_server():
    servers = [
        (METADATA_SERVER_HOST, METADATA_SERVER_PORT),       # Primary connection
        (METADATA_SERVER_HOST, METADATA_SERVER_PORT + 1)    # Backup connection
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
    for i in range(TOTAL_SERVERS): # -> i will check only first 14
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((server_ips[i], DATA_SERVER_BASE_PORT + i))
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
    """Upload a chunk to a data server"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server_ips[server_id], DATA_SERVER_BASE_PORT + server_id))
        
        # Send operation type
        s.sendall('U'.encode('utf-8'))
        
        # Send header
        header = {
                    'user_id': user_id,
                    'chunk_id': chunk_id
                }
        
        header_data = json.dumps(header).encode('utf-8')
        s.sendall(len(header_data).to_bytes(4, byteorder='big'))
        s.sendall(header_data)
        
        # Send chunk data
        s.sendall(len(chunk_data).to_bytes(4, byteorder='big'))
        s.sendall(chunk_data)
        
        # Receive response
        response = s.recv(1024).decode('utf-8')
        response_json = json.loads(response)
        
        s.close()
        return response_json.get('status') == 'success'
    
    except Exception as e:
        print(f"Error uploading chunk to server {server_id}: {e}")
        return False


def download_chunk(server_id, user_id, chunk_id):
    """Download a chunk from a data server"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server_ips[server_id], DATA_SERVER_BASE_PORT + server_id))
        
        # Send operation type
        s.sendall('D'.encode('utf-8'))
        
        # Send header
        header = {'user_id': user_id, 'chunk_id': chunk_id}
        header_data = json.dumps(header).encode('utf-8')
        s.sendall(len(header_data).to_bytes(4, byteorder='big'))
        s.sendall(header_data)
        
        # Receive chunk size
        chunk_size_bytes = s.recv(4)
        if not chunk_size_bytes or len(chunk_size_bytes) != 4:
            s.close()
            return None
        
        chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big')
        
        # Receive chunk data
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
    """Delete a chunk from a data server"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server_ips[server_id], DATA_SERVER_BASE_PORT + server_id))
        
        # Send operation type
        s.sendall('X'.encode('utf-8'))
        
        # Send header
        header = {'user_id': user_id, 'chunk_id': chunk_id}
        header_data = json.dumps(header).encode('utf-8')
        s.sendall(len(header_data).to_bytes(4, byteorder='big'))
        s.sendall(header_data)
        
        # Receive response
        response = s.recv(1024).decode('utf-8')
        response_json = json.loads(response)
        
        s.close()
        return response_json.get('status') == 'success'
    
    except Exception as e:
        print(f"Error deleting chunk from server {server_id}: {e}")
        return False


def register(user_id, password):   ## marking for changing 
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    request = {'action': 'register', 'user_id': user_id, 'password_hash': password_hash, 'salt': salt}
    response = send_request_to_metadata_server(request)
    if response.get('status') == 'success':
        print(f"User {user_id} registered successfully.")
        server_status = get_servers_status()
        for i in range(TOTAL_SERVERS):
            if server_status[i]:
                upload_chunk(i, user_id, 'init', b'')
    else:
        print(f"Registration failed: {response.get('message')}")

      
def authenticate(user_id, password):
    """Authenticate a user and get salt"""
    # Get salt
    request = {
        'action': 'get_salt',
        'user_id': user_id
    }
    
    response = send_request_to_metadata_server(request)
    
    if response.get('status') != 'success':
        print(f"Authentication failed: {response.get('message')}")
        return None
    
    salt = response.get('salt')
    
    # Generate password hash
    password_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    
    # Send authentication request
    request = {
        'action': 'authenticate',
        'user_id': user_id,
        'password_hash': password_hash
    }
    
    response = send_request_to_metadata_server(request)
    
    if response.get('status') == 'success':
        return salt
    else:
        print(f"Authentication failed: {response.get('message')}")
        return None



def upload_file(file_path, user_id, password):  ## marking for changing
    
    salt = authenticate(user_id, password)
    
    if not salt:
        return
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    filename = os.path.basename(file_path)
    
    # Check if file already exists in metadata server
    check_request = {
        'action': 'get_file_metadata',
        'user_id': user_id,
        'filename': filename
    }
    check_response = send_request_to_metadata_server(check_request)

    if check_response.get('status') == 'success':
        print(f"File '{filename}' already exists on the server. Upload aborted.")
        return
    
    server_status = get_servers_status()
    available_servers = sum(server_status)
    
    if available_servers < NUM_DATA_CHUNKS:
        print(f"Not enough servers. Need {NUM_DATA_CHUNKS}, available {available_servers}")
        return
    
    # Calculate chunk size with padding if needed
    data_len = len(file_data)
    chunk_size = (data_len + NUM_DATA_CHUNKS - 1) // NUM_DATA_CHUNKS
    padding_len = chunk_size * NUM_DATA_CHUNKS - data_len
    padded_data = file_data + bytes([0] * padding_len)
    
    encrypted_chunks = []
    chunk_metadata = []
    
    key = derive_key(password, salt)
    
    for i in range(NUM_DATA_CHUNKS):
        chunk = padded_data[i * chunk_size:(i + 1) * chunk_size]
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc_chunk = cipher.encrypt(pad(chunk, AES.block_size))
        hmac_val = compute_hmac(key, enc_chunk)
        chunk_metadata.append({'chunk_no': i, 'iv': binascii.hexlify(iv).decode(), 'hmac': hmac_val})
        encrypted_chunks.append(enc_chunk)
        
    rs = reed_solomon.ReedSolomonCodec(NUM_DATA_CHUNKS, NUM_PARITY_CHUNKS)
        
    parity_chunks = rs.encode(encrypted_chunks)
    
    for i in range(NUM_PARITY_CHUNKS): # no need to encrypt decrypt parity chunks
        iv = secrets.token_bytes(16) # so that db looks uniform
        hmac_val = compute_hmac(key,parity_chunks[i])
        chunk_metadata.append({'chunk_no': 10+i, 'iv': binascii.hexlify(iv).decode(), 'hmac': hmac_val})
    
    all_chunks = encrypted_chunks + parity_chunks
    
    request = {
        'action': 'store_metadata',
        'user_id': user_id, 'filename': filename,
        'chunk_data': chunk_metadata
    }
    
    response = send_request_to_metadata_server(request)
    
    if response.get('status') != 'success':
        print(f"Error storing metadata: {response.get('message')}")
        return
    
    chunk_ids = response.get('chunk_ids')
    
    # Upload chunks to data servers
    success_count = 0
    
    for i in range(len(all_chunks)):
        if i < len(server_status) and server_status[i]:
            if upload_chunk(i, user_id, chunk_ids[i], all_chunks[i]):
                success_count += 1
                print(f"Uploaded chunk {i+1}/{len(all_chunks)} to server {i}")
            else:
                print(f"Failed to upload chunk {i+1}/{len(all_chunks)} to server {i}")
    
    if success_count == len(all_chunks):
        print(f"Successfully uploaded {filename}")
    else:
        print(f"Warning: Only uploaded {success_count}/{len(all_chunks)} chunks")
        

def list_files(user_id, password):
    """List files for a user"""
    # Authenticate user
    if not authenticate(user_id, password):
        return
    
    # Request file list
    request = {
        'action': 'list_files',
        'user_id': user_id
    }
    
    response = send_request_to_metadata_server(request)
    
    if response.get('status') == 'success':
        files = response.get('files', [])
        
        if not files:
            print("No files found")
        else:
            print("Files:")
            for file in files:
                print(f"- {file}")
    else:
        print(f"Error listing files: {response.get('message')}")


def download_file(filename, user_id, password):
    salt = authenticate(user_id, password)
    if not salt:
        return
    
    request = {
        'action': 'get_file_metadata',
        'user_id': user_id,
        'filename': filename
    }
    
    response = send_request_to_metadata_server(request)
    
    if response.get('status') != 'success':
        print(f"Error: {response.get('message')}")
        return
    
    metadata = response.get('metadata')
    
    server_status = get_servers_status()
    available_servers = sum(server_status)
    
    if available_servers < NUM_DATA_CHUNKS:
        print(f"Not enough servers available. Need at least {NUM_DATA_CHUNKS}, but only {available_servers} available.")
        return
    
    key = derive_key(password, salt)
    
    chunks, chunk_indices = [], []
    
    # First try to download data chunks (0-9)
    for i in range(NUM_DATA_CHUNKS):
        if server_status[i]:
            
            chunk_meta = next((m for m in metadata if m['chunk_no'] == i), None)
            if not chunk_meta:
                print(f"Error: Missing metadata for chunk {i}")
                continue
            
            encrypted_chunk = download_chunk(i, user_id, chunk_meta['chunk_id'])
            
            if encrypted_chunk:
                # Verify HMAC
                if verify_hmac(key, encrypted_chunk, chunk_meta['hmac']):
                    chunks.append(encrypted_chunk)
                    chunk_indices.append(i)
                    print(f"Downloaded and verified chunk {i+1}/{NUM_DATA_CHUNKS + NUM_PARITY_CHUNKS}")
                else:
                    print(f"HMAC verification failed for chunk {i}")
            else:
                print(f"Failed to download chunk {i} from server {i}")
                
    if len(chunks) < NUM_DATA_CHUNKS:
        # try to get parity chunks
        for i in range(NUM_DATA_CHUNKS, NUM_DATA_CHUNKS + NUM_PARITY_CHUNKS):
            if len(chunks) >= NUM_DATA_CHUNKS:
                break
                
            if i < len(server_status) and server_status[i]:
                chunk_meta = next((m for m in metadata if m['chunk_no'] == i), None)
                if not chunk_meta:
                    print(f"Error: Missing metadata for chunk {i}")
                    continue
                
                parity_chunk = download_chunk(i, user_id, chunk_meta['chunk_id'])
                
                if parity_chunk:
                    if verify_hmac(key, parity_chunk, chunk_meta['hmac']):
                        chunks.append(parity_chunk)
                        chunk_indices.append(i)
                        print(f"Downloaded and verified parity chunk {i+1}/{NUM_DATA_CHUNKS + NUM_PARITY_CHUNKS}")
                    else:
                        print(f"HMAC verification failed for chunk {i}")
                else:
                    print(f"Failed to download chunk {i} from server {i}")
        
        if len(chunks) < NUM_DATA_CHUNKS:
            print(f"Not enough chunks to recover the file. Need {NUM_DATA_CHUNKS} chunks, but only have {len(chunks)}.")
            return
    
    # Check if we have all original data chunks (no need for Reed-Solomon recovery)
    if len(chunks) >= NUM_DATA_CHUNKS and all(i < NUM_DATA_CHUNKS for i in chunk_indices[:NUM_DATA_CHUNKS]):
        data_chunks = []
        # Only use the first NUM_DATA_CHUNKS chunks
        for i in range(NUM_DATA_CHUNKS):
            chunk_no = chunk_indices[i]
            chunk_meta = next((m for m in metadata if m['chunk_no'] == chunk_no), None)
            
            if not chunk_meta:
                print(f"Error: Missing metadata for chunk {chunk_no}")
                continue
            
            iv = bytes.fromhex(chunk_meta['iv'])
            
            try:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(chunks[i]), AES.block_size)
                data_chunks.append(bytearray(decrypted))
                
            except Exception as e:
                print(f"Error decrypting chunk {chunk_no}: {e}")
                return
            
        reconstructed_data = b''.join(data_chunks)
        
    else:
        # Need to recover using Reed-Solomon
        rs_codec = reed_solomon.ReedSolomonCodec(NUM_DATA_CHUNKS, NUM_PARITY_CHUNKS)
        try:
            recovered_chunks = rs_codec.decode(chunks, chunk_indices)
            
            # Decrypt the recovered data chunks
            decrypted_chunks = []
            for i in range(NUM_DATA_CHUNKS):
                chunk_meta = next((m for m in metadata if m['chunk_no'] == i), None)
                if not chunk_meta:
                    print(f"Error: Missing metadata for chunk {i}")
                    return
                
                iv = bytes.fromhex(chunk_meta['iv'])
                
                try:
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted = unpad(cipher.decrypt(bytes(recovered_chunks[i])), AES.block_size)
                    decrypted_chunks.append(decrypted)
                except Exception as e:
                    print(f"Error decrypting recovered chunk {i}: {e}")
                    return
            
            reconstructed_data = b''.join(decrypted_chunks)
        except Exception as e:
            print(f"Error reconstructing file using Reed-Solomon: {e}")
            return
    
    # Remove any padding bytes
    file_size = len(reconstructed_data)
    
    # Save the file
    try:
        os.makedirs("VaultCLI-downloads", exist_ok=True)
        file_path = os.path.join("VaultCLI-downloads", filename)
        with open(file_path, 'wb') as f:
            f.write(reconstructed_data)
        print(f"Successfully downloaded and saved {filename} ({file_size} bytes)")
    except Exception as e:
        print(f"Error saving file: {e}")
        

def delete_file(filename, user_id, password):
    
    if not authenticate(user_id, password):
        return
    
    request = {
        'action': 'get_file_metadata',
        'user_id': user_id,
        'filename': filename
    }
    
    response = send_request_to_metadata_server(request)
    
    if response.get('status') != 'success':
        print(f"Error: {response.get('message')}")
        return
    
    metadata = response.get('metadata')
    
    print(f"Deleting {filename}...")
    
    for m in metadata:
        delete_chunk(m['chunk_no'], user_id, m['chunk_id'])
        
    request = {
        'action': 'delete_file',
        'user_id': user_id,
        'filename': filename
    }
    
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
        print("Commands:")
        print("python client.py upload <file_path> <user_id> <password>")
        print("python client.py list <user_id> <password>")
        print("python client.py download <filename> <user_id> <password>")
        print("python client.py delete <filename> <user_id> <password>")


if __name__ == "__main__":
    main()
