# VaultCLI - Distributed File Storage Simulation

A secure, fault-tolerant distributed storage system with encryption, Reed-Solomon error correction, and data redundancy.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Setup and Configuration](#setup-and-configuration)
  - [Metadata Servers](#metadata-servers)
  - [Data Servers](#data-servers)
- [Usage](#usage)
  - [Client Commands](#client-commands)
  - [Examples](#examples)
- [Technical Details](#technical-details)
  - [Architecture](#architecture)
  - [Security Features](#security-features)
  - [Fault Tolerance](#fault-tolerance)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

## Overview

VaultCLI is a command-line distributed storage system that ensures data security and availability through encryption, redundancy, and erasure coding. Files are split into chunks, encrypted, and distributed across multiple servers with parity data to recover from server failures.

## Features

- **Secure Storage**: AES-256 encryption with HMAC authentication
- **Fault Tolerance**: Reed-Solomon error correction allows recovery even when multiple servers fail
- **High Availability**: Primary-backup metadata replication
- **User Authentication**: Secure password-based authentication
- **Simple CLI**: Easy-to-use command-line interface

## Prerequisites

- Python 3.6+
- Network connectivity between servers (or local testing environment)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/vaultcli.git
   cd vaultcli
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Setup and Configuration

### Metadata Servers

You need to run two metadata servers: a primary server and a backup server.

1. **Start the primary metadata server**:
   ```bash
   python metadata_backup/metadata_server.py --port 8000 --db metadata_primary.db --role primary --peer_port 8001
   ```

2. **Start the backup metadata server**:
   ```bash
   python metadata_backup/metadata_server.py --port 8001 --db metadata_backup.db --role backup
   ```

These servers store user information and file metadata, with the primary server replicating changes to the backup.

### Data Servers

You need to start 14 data servers, each with a unique ID (0-13):

```bash
# Create directories for each server if they don't exist
mkdir -p servers/server_{0..13}

# Start each data server with its ID
# Server 0
python servers/server_1/server.py 0
# Server 1
python servers/server_1/server.py 1
# ... and so on until Server 13
python servers/server_1/server.py 13
```

For convenience in a test environment, you can use a simple bash script to start all servers:

```bash
#!/bin/bash
# start_servers.sh

# Start metadata servers
python metadata_backup/metadata_server.py --port 8000 --db metadata_primary.db --role primary --peer_port 8001 &
python metadata_backup/metadata_server.py --port 8001 --db metadata_backup.db --role backup &

# Start data servers
for i in {0..13}
do
  python servers/server_1/server.py $i &
done

echo "All servers started."
```

Make the script executable: `chmod +x start_servers.sh`

## Usage

### Client Commands

The client offers five main commands:

1. **Register a new user**:
   ```bash
   python client/client.py register <username> <password>
   ```

2. **Upload a file**:
   ```bash
   python client/client.py upload <file_path> <username> <password>
   ```

3. **List files**:
   ```bash
   python client/client.py list <username> <password>
   ```

4. **Download a file**:
   ```bash
   python client/client.py download <filename> <username> <password>
   ```

5. **Delete a file**:
   ```bash
   python client/client.py delete <filename> <username> <password>
   ```

### Examples

```bash
# Register a new user
python client/client.py register alice secure_password123

# Upload a file
python client/client.py upload ~/Documents/important.pdf alice secure_password123

# List all files
python client/client.py list alice secure_password123

# Download a file
python client/client.py download important.pdf alice secure_password123

# Delete a file
python client/client.py delete important.pdf alice secure_password123
```

## Technical Details

### Architecture

The system consists of three main components:

1. **Client**: Handles user interaction, file splitting, encryption, and Reed-Solomon encoding/decoding
2. **Metadata Servers**: Store user credentials and file metadata (which chunks belong to which file)
3. **Data Servers**: Store the actual encrypted file chunks

### Security Features

- **Encryption**: AES-256 in CBC mode with random IVs for each chunk
- **Authentication**: Passwords are salted and hashed using SHA-256
- **Data Integrity**: HMAC verification ensures chunk integrity
- **Key Derivation**: PBKDF2 with 100,000 iterations for deriving encryption keys

### Fault Tolerance

- **Reed-Solomon Coding**: Files are split into 10 data chunks plus 4 parity chunks
- **Server Redundancy**: System can recover data even if up to 4 servers are unavailable
- **Metadata Replication**: Primary-backup architecture for metadata servers

### Data Flow - Upload

1. File is split into 10 equal chunks
2. Each chunk is encrypted with AES-256
3. Reed-Solomon encoding creates 4 additional parity chunks
4. All 14 chunks are distributed across data servers
5. Metadata is stored in the metadata servers

### Data Flow - Download

1. Metadata is retrieved from metadata servers
2. System attempts to download chunks from all available servers
3. If some chunks are unavailable, Reed-Solomon decoding reconstructs them
4. Chunks are verified using HMAC, decrypted, and reassembled
5. Original file is saved in the VaultCLI-downloads directory

## Project Structure

```
project_root/
├── client/
│   ├── client.py          # Client application
│   └── reed_solomon.py    # Reed-Solomon encoding implementation
├── metadata_backup/
│   └── metadata_server.py # backup metadata server implementation
├── metadata_server/
│   └── metadata_server.py # primary metadata server implementation
├── servers/
│   └── server_1/
│       └── server.py      # Data server implementation
├── VaultCLI-downloads/    # Default download location
└── requirements.txt       # Project dependencies
```

## Troubleshooting

- **Connection errors**: Ensure all servers are running and accessible
- **Authentication failures**: Verify username and password are correct
- **Download failures**: At least 10 out of 14 servers must be available
- **Chunk errors**: If HMAC verification fails, the chunk may be corrupted
- **Missing downloads**: Check the VaultCLI-downloads directory

## How It Works

VaultCLI uses erasure coding (Reed-Solomon) to provide fault tolerance. When you upload a file:

1. The file is split into 10 data chunks
2. 4 parity chunks are generated
3. Each chunk is encrypted and stored on a different server

This means any 10 out of 14 chunks are sufficient to reconstruct the original file. The system provides:

- **Data confidentiality** through encryption
- **Availability** through redundancy
- **Integrity** through HMAC verification
- **Fault tolerance** through erasure coding

When systems fail, the client can still recover data as long as at least 10 servers are available, making this a highly reliable distributed storage solution.