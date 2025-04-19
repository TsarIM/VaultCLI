import socket
import json
import os
import threading
import sys

class DataServer:
    def __init__(self, server_id, host='0.0.0.0', port=8100):
        self.server_id = server_id
        self.host = host
        self.port = port + server_id  # Each server has a unique port
        self.storage_dir = "storage"
        self.ensure_storage_dir()
        
    def ensure_storage_dir(self):
        """Ensure the storage directory exists"""
        os.makedirs(self.storage_dir, exist_ok=True)
        
    def create_user_dir(self, user_id):
        """Create directory for a user"""
        user_dir = os.path.join(self.storage_dir, user_id)
        os.makedirs(user_dir, exist_ok=True)
        return user_dir
    
    def handle_upload(self, client_socket):
        """Handle file chunk upload"""
        try:
            # Receive JSON header
            header_size_bytes = client_socket.recv(4)
            header_size = int.from_bytes(header_size_bytes, byteorder='big')
            
            header_data = client_socket.recv(header_size).decode('utf-8')
            header = json.loads(header_data)
            
            user_id = header.get('user_id')
            chunk_id = header.get('chunk_id')
            
            # Ensure user directory exists
            user_dir = self.create_user_dir(user_id)
            
            # Receive the actual chunk data
            chunk_size_bytes = client_socket.recv(4)
            chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big')
            
            chunk_data = b''
            remaining = chunk_size
            
            while remaining > 0:
                data = client_socket.recv(min(4096, remaining))
                if not data:
                    break
                chunk_data += data
                remaining -= len(data)
            
            # Write chunk to file
            chunk_file = os.path.join(user_dir, f"{chunk_id}.chunk")
            with open(chunk_file, 'wb') as f:
                f.write(chunk_data)
            
            response = {'status': 'success', 'message': 'Chunk uploaded successfully'}
            client_socket.sendall(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            response = {'status': 'error', 'message': str(e)}
            client_socket.sendall(json.dumps(response).encode('utf-8'))
    
    def handle_download(self, client_socket):
        """Handle file chunk download"""
        try:
            # Receive JSON header
            header_size_bytes = client_socket.recv(4)
            header_size = int.from_bytes(header_size_bytes, byteorder='big')
            
            header_data = client_socket.recv(header_size).decode('utf-8')
            header = json.loads(header_data)
            
            user_id = header.get('user_id')
            chunk_id = header.get('chunk_id')
            
            # Construct path to the chunk file
            chunk_file = os.path.join(self.storage_dir, user_id, f"{chunk_id}.chunk")
            
            if not os.path.exists(chunk_file):
                response = {'status': 'error', 'message': 'Chunk not found'}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                return
            
            # Read chunk data
            with open(chunk_file, 'rb') as f:
                chunk_data = f.read()
            
            # Send chunk size
            client_socket.sendall(len(chunk_data).to_bytes(4, byteorder='big'))
            
            # Send chunk data
            client_socket.sendall(chunk_data)
            
        except Exception as e:
            try:
                response = {'status': 'error', 'message': str(e)}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
            except:
                pass
    
    def handle_delete(self, client_socket):
        """Handle file chunk deletion"""
        try:
            # Receive JSON header
            header_size_bytes = client_socket.recv(4)
            header_size = int.from_bytes(header_size_bytes, byteorder='big')
            
            header_data = client_socket.recv(header_size).decode('utf-8')
            header = json.loads(header_data)
            
            user_id = header.get('user_id')
            chunk_id = header.get('chunk_id')
            
            # Construct path to the chunk file
            chunk_file = os.path.join(self.storage_dir, user_id, f"{chunk_id}.chunk")
            
            if os.path.exists(chunk_file):
                os.remove(chunk_file)
                response = {'status': 'success', 'message': 'Chunk deleted'}
            else:
                response = {'status': 'error', 'message': 'Chunk not found'}
            
            client_socket.sendall(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            response = {'status': 'error', 'message': str(e)}
            client_socket.sendall(json.dumps(response).encode('utf-8'))
    
    def handle_client(self, client_socket):
        """Handle client connection"""
        try:
            # Receive operation type
            op_type = client_socket.recv(1).decode('utf-8')
            
            if op_type == 'U':  # Upload
                self.handle_upload(client_socket)
            elif op_type == 'D':  # Download
                self.handle_download(client_socket)
            elif op_type == 'X':  # Delete
                self.handle_delete(client_socket)
            else:
                response = {'status': 'error', 'message': 'Invalid operation'}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
        
        except Exception as e:
            print(f"Error handling client: {e}")
        
        finally:
            client_socket.close()
    
    def start(self):
        """Start the data server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"Data server {self.server_id} started on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"Connection from {addr}")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
        
        except KeyboardInterrupt:
            print(f"Shutting down data server {self.server_id}...")
        
        finally:
            server_socket.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python server.py <server_id>")
        sys.exit(1)
    
    server_id = int(sys.argv[1])
    server = DataServer(server_id)
    server.start()