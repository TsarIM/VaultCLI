import argparse
import socket
import json
import os
import sys
import hashlib
import secrets
import hmac
import binascii
from Crypto.Cipher import AES #type: ignore
from Crypto.Util.Padding import pad, unpad #type: ignore
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
    """Connect to the metadata server"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((METADATA_SERVER_HOST, METADATA_SERVER_PORT))
        return s
    except Exception as e:
        print(f"Error connecting to metadata server: {e}")
        sys.exit(1)


def send_request_to_metadata_server(request):
    """Send a request to the metadata server and get the response"""
    try:
        s = connect_to_metadata_server()
        s.sendall(json.dumps(request).encode('utf-8'))
        response = s.recv(8192).decode('utf-8')
        s.close()
        return json.loads(response)
    except Exception as e:
        print(f"Error communicating with metadata server: {e}")
        sys.exit(1)


def get_servers_status():
    """Check which data servers are available"""
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
    """Derive AES key from password and salt using PBKDF2"""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 100000)


def compute_hmac(key, data):
    """Compute HMAC for data using key"""
    h = hmac.new(key, data, hashlib.sha256)
    return h.hexdigest()


def verify_hmac(key, data, hmac_val):
    """Verify HMAC for data using key"""
    computed = compute_hmac(key, data)
    return hmac.compare_digest(computed, hmac_val)


def upload_chunk(server_id, user_id, chunk_id, chunk_data):
    """Upload a chunk to a data server"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', DATA_SERVER_BASE_PORT + server_id))
        
        # Send operation type
        s.sendall('U'.encode('utf-8'))
        
        # Send header
        header = {'user_id': user_id, 'chunk_id': chunk_id}
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
        s.connect(('127.0.0.1', DATA_SERVER_BASE_PORT + server_id))
        
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
        s.connect(('127.0.0.1', DATA_SERVER_BASE_PORT + server_id))
        
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


def register(user_id, password):
    """Register a new user"""
    # Generate salt
    salt = secrets.token_hex(16)
    
    # Generate password hash
    password_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    
    # Send registration request to metadata server
    request = {
        'action': 'register',
        'user_id': user_id,
        'password_hash': password_hash,
        'salt': salt
    }
    
    response = send_request_to_metadata_server(request)
    
    if response.get('status') == 'success':
        print(f"User {user_id} registered successfully.")
        
        # Create user directories on all data servers
        server_status = get_servers_status()
        created_dirs = 0
        
        for i in range(DATA_SERVER_COUNT):
            if server_status[i]:
                try:
                    # We'll send an empty upload to create the directory
                    if upload_chunk(i, user_id, 'init', b''):
                        created_dirs += 1
                except:
                    pass
        
        if created_dirs == DATA_SERVER_COUNT:
            print(f"Created user directories on all {DATA_SERVER_COUNT} data servers.")
        else:
            print(f"Warning: Only created user directories on {created_dirs}/{DATA_SERVER_COUNT} data servers.")
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


def upload_file(file_path, user_id, password):
    """Upload a file"""
    # Authenticate user
    salt = authenticate(user_id, password)
    if not salt:
        return
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    
    # Read file
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    # Get filename
    filename = os.path.basename(file_path)
    
    # Check server availability
    server_status = get_servers_status()
    available_servers = sum(server_status)
    
    if available_servers < NUM_DATA_CHUNKS:
        print(f"Not enough servers available. Need at least {NUM_DATA_CHUNKS}, but only {available_servers} available.")
        return
    
    print(f"Uploading {filename} ({len(file_data)} bytes)...")
    
    # Calculate chunk size with padding if needed
    data_len = len(file_data)
    chunk_size = (data_len + NUM_DATA_CHUNKS - 1) // NUM_DATA_CHUNKS
    padding_len = chunk_size * NUM_DATA_CHUNKS - data_len
    padded_data = file_data + bytes([0] * padding_len)
    
    # Divide into chunks
    data_chunks = []
    for i in range(NUM_DATA_CHUNKS):
        chunk = padded_data[i * chunk_size:(i + 1) * chunk_size]
        data_chunks.append(bytearray(chunk))
    
    # Generate key from password
    key = derive_key(password, salt)
    
    # Initialize Reed-Solomon codec
    rs_codec = reed_solomon.ReedSolomonCodec(NUM_DATA_CHUNKS, NUM_PARITY_CHUNKS)
    
    # Generate parity chunks
    parity_chunks = rs_codec.encode(data_chunks)
    
    # Combine all chunks
    all_chunks = data_chunks + parity_chunks
    
    # Prepare metadata
    chunk_metadata = []
    encrypted_chunks = []
    
    for i in range(len(all_chunks)):
        # Generate IV for each chunk
        iv = secrets.token_bytes(16)
        
        # Encrypt chunk
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_chunk = cipher.encrypt(pad(all_chunks[i], AES.block_size))
        
        # Compute HMAC
        chunk_hmac = compute_hmac(key, encrypted_chunk)
        
        # Add to metadata
        chunk_metadata.append({
            'chunk_no': i,
            'iv': binascii.hexlify(iv).decode('utf-8'),
            'hmac': chunk_hmac
        })
        
        encrypted_chunks.append(encrypted_chunk)
    
    # Store metadata on metadata server
    request = {
        'action': 'store_metadata',
        'user_id': user_id,
        'filename': filename,
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
            if upload_chunk(i, user_id, chunk_ids[i], encrypted_chunks[i]):
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
    """Download a file"""
    # Authenticate user
    salt = authenticate(user_id, password)
    if not salt:
        return
    
    # Get file metadata
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
    
    # Check server availability
    server_status = get_servers_status()
    available_servers = sum(server_status)
    
    if available_servers < NUM_DATA_CHUNKS:
        print(f"Not enough servers available. Need at least {NUM_DATA_CHUNKS}, but only {available_servers} available.")
        return
    
    # Generate key from password
    key = derive_key(password, salt)
    
    # Download chunks
    chunks = []
    chunk_indices = []
    
    print(f"Downloading {filename}...")
    
    # First try to download data chunks (0-9)
    for i in range(NUM_DATA_CHUNKS):
        if i < len(server_status) and server_status[i]:
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
    
    # If we have all data chunks, no need for parity
    if len(chunks) == NUM_DATA_CHUNKS and all(i < NUM_DATA_CHUNKS for i in chunk_indices):
        pass
    # If we have less than MIN_DATA_CHUNKS chunks, can't recover
    elif len(chunks) < NUM_DATA_CHUNKS:
        # Try to get parity chunks
        for i in range(NUM_DATA_CHUNKS, NUM_DATA_CHUNKS + NUM_PARITY_CHUNKS):
            if len(chunks) >= NUM_DATA_CHUNKS:
                break
                
            if i < len(server_status) and server_status[i]:
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
                        print(f"Downloaded and verified parity chunk {i+1}/{NUM_DATA_CHUNKS + NUM_PARITY_CHUNKS}")
                    else:
                        print(f"HMAC verification failed for chunk {i}")
                else:
                    print(f"Failed to download chunk {i} from server {i}")
        
        if len(chunks) < NUM_DATA_CHUNKS:
            print(f"Not enough chunks to recover the file. Need {NUM_DATA_CHUNKS} chunks, but only have {len(chunks)}.")
            return
    
    # Decrypt chunks
    decrypted_chunks = []
    
    for i, encrypted_chunk in enumerate(chunks):
        chunk_no = chunk_indices[i]
        chunk_meta = next((m for m in metadata if m['chunk_no'] == chunk_no), None)
        
        if not chunk_meta:
            print(f"Error: Missing metadata for chunk {chunk_no}")
            continue
        
        iv = bytes.fromhex(chunk_meta['iv'])
        
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_chunk), AES.block_size)
            decrypted_chunks.append(bytearray(decrypted))
        except Exception as e:
            print(f"Error decrypting chunk {chunk_no}: {e}")
            return
    
    # Use Reed-Solomon to reconstruct if needed
    if len(decrypted_chunks) == NUM_DATA_CHUNKS and all(i < NUM_DATA_CHUNKS for i in chunk_indices):
        # We have all original data chunks, no need for reconstruction
        ordered_chunks = [None] * NUM_DATA_CHUNKS
        for i, chunk_idx in enumerate(chunk_indices):
            if chunk_idx < NUM_DATA_CHUNKS:
                ordered_chunks[chunk_idx] = decrypted_chunks[i]
        
        reconstructed_chunks = ordered_chunks
    else:
        # We need reconstruction
        print("Reconstructing file using Reed-Solomon...")
        rs_codec = reed_solomon.ReedSolomonCodec(NUM_DATA_CHUNKS, NUM_PARITY_CHUNKS)
        try:
            reconstructed_chunks = rs_codec.decode(decrypted_chunks, chunk_indices)
        except Exception as e:
            print(f"Error reconstructing file: {e}")
            return
    
    # Combine chunks to reconstruct the file
    reconstructed_data = b''.join(reconstructed_chunks)
    
    # Remove padding
    file_size = len(reconstructed_data)
    
    # Save the file
    try:
        with open(filename, 'wb') as f:
            f.write(reconstructed_data)
        print(f"Successfully downloaded and saved {filename} ({file_size} bytes)")
    except Exception as e:
        print(f"Error saving file: {e}")


def delete_file(filename, user_id, password):
    """Delete a file"""
    # Authenticate user
    if not authenticate(user_id, password):
        return
    
    # Get file metadata
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
    
    # Delete chunks from data servers
    for chunk_meta in metadata:
        chunk_no = chunk_meta['chunk_no']
        chunk_id = chunk_meta['chunk_id']
        
        if chunk_no < DATA_SERVER_COUNT:
            if delete_chunk(chunk_no, user_id, chunk_id):
                print(f"Deleted chunk {chunk_no} from server {chunk_no}")
            else:
                print(f"Failed to delete chunk {chunk_no} from server {chunk_no}")
    
    # Delete metadata
    request = {
        'action': 'delete_file',
        'user_id': user_id,
        'filename': filename
    }
    
    response = send_request_to_metadata_server(request)
    
    if response.get('status') == 'success':
        print(f"Successfully deleted {filename}")
    else:
        print(f"Error deleting metadata: {response.get('message')}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Distributed Storage Client')
    
    # Define subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Register command
    register_parser = subparsers.add_parser('register', help='Register a new user')
    register_parser.add_argument('user_id', help='User ID')
    register_parser.add_argument('password', help='Password')
    
    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload a file')
    upload_parser.add_argument('file_path', help='Path to the file')
    upload_parser.add_argument('user_id', help='User ID')
    upload_parser.add_argument('password', help='Password')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all files')
    list_parser.add_argument('user_id', help='User ID')
    list_parser.add_argument('password', help='Password')
    
    # Download command
    download_parser = subparsers.add_parser('download', help='Download a file')
    download_parser.add_argument('filename', help='Filename to download')
    download_parser.add_argument('user_id', help='User ID')
    download_parser.add_argument('password', help='Password')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a file')
    delete_parser.add_argument('filename', help='Filename to delete')
    delete_parser.add_argument('user_id', help='User ID')
    delete_parser.add_argument('password', help='Password')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute command
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