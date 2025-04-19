# metadata_server.py
import socket
import json
import sqlite3
import os
import threading
import argparse

class MetadataServer:
    def __init__(self, host='0.0.0.0', port=8000, db_path='metadata.db', role='primary', peer_port=None):
        self.host = host
        self.port = port
        self.db_path = db_path
        self.role = role
        self.peer_port = peer_port
        self.initialize_db()

    def initialize_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            user_id TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Files (
            chunk_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            chunk_no INTEGER NOT NULL,
            iv TEXT NOT NULL,
            hmac TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES Users(user_id),
            UNIQUE(user_id, filename, chunk_no)
        )''')
        conn.commit()
        conn.close()

    def replicate(self, request):
        if self.role != 'primary' or not self.peer_port:
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', self.peer_port))
            request['action'] = 'replicate_' + request['action']
            s.sendall(json.dumps(request).encode('utf-8'))
            s.close()
        except Exception as e:
            print(f"[!] Replication to backup failed: {e}")

    def register_user(self, user_id, password_hash, salt):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO Users (user_id, salt, password_hash) VALUES (?, ?, ?)",
                (user_id, salt, password_hash)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def authenticate_user(self, user_id, password_hash):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM Users WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == password_hash

    def get_user_salt(self, user_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT salt FROM Users WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def store_file_metadata(self, user_id, filename, chunk_data):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM Files WHERE user_id = ? AND filename = ?", (user_id, filename))
        if cursor.fetchone()[0] > 0:
            cursor.execute("DELETE FROM Files WHERE user_id = ? AND filename = ?", (user_id, filename))
        chunk_ids = []
        for chunk in chunk_data:
            cursor.execute(
                "INSERT INTO Files (user_id, filename, chunk_no, iv, hmac) VALUES (?, ?, ?, ?, ?)",
                (user_id, filename, chunk['chunk_no'], chunk['iv'], chunk['hmac'])
            )
            chunk_ids.append(cursor.lastrowid)
        conn.commit()
        conn.close()
        return chunk_ids

    def get_user_files(self, user_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT filename FROM Files WHERE user_id = ?", (user_id,))
        results = cursor.fetchall()
        conn.close()
        return [r[0] for r in results]

    def get_file_metadata(self, user_id, filename):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT chunk_id, chunk_no, iv, hmac FROM Files WHERE user_id = ? AND filename = ? ORDER BY chunk_no",
            (user_id, filename)
        )
        results = cursor.fetchall()
        conn.close()
        return [{'chunk_id': c_id, 'chunk_no': c_no, 'iv': iv, 'hmac': hmac} for c_id, c_no, iv, hmac in results]

    def delete_file_metadata(self, user_id, filename):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Files WHERE user_id = ? AND filename = ?", (user_id, filename))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted > 0

    def recv_all(self, sock):
        data = b''
        while True:
            part = sock.recv(4096)
            if not part:
                break
            data += part
            if len(part) < 4096:
                break
        return data.decode('utf-8')

    def handle_action(self, request):
        action = request.get('action')

        if action.startswith('replicate_'):
            action = action.replace('replicate_', '')
            request['action'] = action
            self.handle_action(request)
            return {'status': 'success'}

        if action == 'register':
            success = self.register_user(request['user_id'], request['password_hash'], request['salt'])
            if self.role == 'primary':
                self.replicate(request)
            return {'status': 'success'} if success else {'status': 'error', 'message': 'User exists'}

        elif action == 'get_salt':
            salt = self.get_user_salt(request['user_id'])
            return {'status': 'success', 'salt': salt} if salt else {'status': 'error', 'message': 'User not found'}

        elif action == 'authenticate':
            if self.authenticate_user(request['user_id'], request['password_hash']):
                return {'status': 'success'}
            else:
                return {'status': 'error', 'message': 'Authentication failed'}

        elif action == 'store_metadata':
            chunk_ids = self.store_file_metadata(request['user_id'], request['filename'], request['chunk_data'])
            if self.role == 'primary':
                self.replicate(request)
            return {'status': 'success', 'chunk_ids': chunk_ids}

        elif action == 'list_files':
            files = self.get_user_files(request['user_id'])
            return {'status': 'success', 'files': files}

        elif action == 'get_file_metadata':
            metadata = self.get_file_metadata(request['user_id'], request['filename'])
            return {'status': 'success', 'metadata': metadata} if metadata else {'status': 'error', 'message': 'File not found'}

        elif action == 'delete_file':
            deleted = self.delete_file_metadata(request['user_id'], request['filename'])
            if self.role == 'primary':
                self.replicate(request)
            return {'status': 'success'} if deleted else {'status': 'error', 'message': 'File not found'}

        return {'status': 'error', 'message': 'Unknown action'}

    def handle_client(self, client_socket):
        try:
            data = self.recv_all(client_socket)
            request = json.loads(data)
            response = self.handle_action(request)
            client_socket.sendall(json.dumps(response).encode('utf-8'))
        except Exception as e:
            print(f"[!] Error: {e}")
            try:
                client_socket.sendall(json.dumps({'status': 'error', 'message': str(e)}).encode('utf-8'))
            except:
                pass
        finally:
            client_socket.close()

    def start(self):
        print(f"[+] {self.role.upper()} Metadata Server started on {self.host}:{self.port}")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        try:
            while True:
                client, addr = server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()
        except KeyboardInterrupt:
            print("Shutting down...")
        finally:
            server_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--db', type=str, required=True)
    parser.add_argument('--role', choices=['primary', 'backup'], required=True)
    parser.add_argument('--peer_port', type=int, required=False)
    args = parser.parse_args()

    MetadataServer(
        host='0.0.0.0',
        port=args.port,
        db_path=args.db,
        role=args.role,
        peer_port=args.peer_port
    ).start()
