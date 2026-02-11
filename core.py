# Core Cryptography and Network Module for CryptXfer
# Author: Nguyen Duong Quang
# www.m3rooted.com

import socket
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import struct
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
MIN_PASSWORD_LENGTH = 8
PORT_MIN = 1
PORT_MAX = 65535
SALT_LENGTH = 16
IV_LENGTH = 16
HMAC_LENGTH = 32


def derive_key(password, salt):
    """Derive encryption key from password using PBKDF2-HMAC-SHA256 with random salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def pad_data(data):
    """Pad data using PKCS7 padding"""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def unpad_data(data):
    """Remove PKCS7 padding from data"""
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data


def compute_hmac(derived_key, data):
    """Compute HMAC-SHA256 for data integrity"""
    h = hmac.HMAC(derived_key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def verify_hmac(derived_key, data, expected_hmac):
    """Verify HMAC-SHA256 for data integrity"""
    h = hmac.HMAC(derived_key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(expected_hmac)
        return True
    except Exception:
        return False


def validate_port(port_str):
    """Validate port number"""
    try:
        port = int(port_str)
        if PORT_MIN <= port <= PORT_MAX:
            return True, port
        return False, None
    except ValueError:
        return False, None


def validate_password(password):
    """Validate password strength"""
    return len(password) >= MIN_PASSWORD_LENGTH


def validate_host(host):
    """Validate host is not empty"""
    return host and host.strip() != ""


def send_file(sock, filename, password):
    """Send encrypted file with HMAC integrity check"""
    # Check file size
    file_size = os.path.getsize(filename)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File size ({file_size} bytes) exceeds maximum allowed size ({MAX_FILE_SIZE} bytes)")
    
    logger.info(f"Sending file: {filename} (Size: {file_size} bytes)")
    
    # Generate random salt
    salt = os.urandom(SALT_LENGTH)
    derived_key = derive_key(password, salt)
    
    with open(filename, 'rb') as file:
        file_data = file.read()
        padded_data = pad_data(file_data)

        # Generate random IV
        iv = os.urandom(IV_LENGTH)
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Compute HMAC for integrity
        hmac_value = compute_hmac(derived_key, iv + ciphertext)

        # Send filename
        filename_bytes = os.path.basename(filename).encode()
        sock.sendall(struct.pack('I', len(filename_bytes)) + filename_bytes)
        
        # Send: salt + IV + ciphertext + HMAC
        sock.sendall(salt + iv + ciphertext + hmac_value)
    
    logger.info("File sent successfully")


def decrypt_data(password, data):
    """Decrypt data with HMAC verification"""
    # Extract components: salt + IV + ciphertext + HMAC
    if len(data) < SALT_LENGTH + IV_LENGTH + HMAC_LENGTH:
        raise ValueError("Invalid data format")
    
    salt = data[:SALT_LENGTH]
    iv = data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    hmac_value = data[-HMAC_LENGTH:]
    ciphertext = data[SALT_LENGTH + IV_LENGTH:-HMAC_LENGTH]
    
    # Derive key from password and salt
    derived_key = derive_key(password, salt)
    
    # Verify HMAC first
    if not verify_hmac(derived_key, iv + ciphertext, hmac_value):
        raise ValueError("HMAC verification failed - data may have been tampered with")
    
    logger.info("HMAC verification passed")
    
    # Decrypt
    backend = default_backend()
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)
    return unpadded_data


def receive_file(password, port):
    """Receive encrypted file with integrity verification"""
    host = '0.0.0.0'

    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.bind((host, port))
    receiver_socket.listen(1)
    logger.info(f"Receiver is listening on port {port}...")

    client_socket, client_address = receiver_socket.accept()
    logger.info(f"Connection established with: {client_address}")

    try:
        filename_len = struct.unpack('I', client_socket.recv(4))[0]
        filename = client_socket.recv(filename_len).decode()

        encrypted_data = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            encrypted_data += chunk
            
            # Check size limit while receiving
            if len(encrypted_data) > MAX_FILE_SIZE + 1024:
                raise ValueError("Received data exceeds maximum file size")

        logger.info(f"Received {len(encrypted_data)} bytes")
        decrypted_data = decrypt_data(password, encrypted_data)
        
        with open(filename, 'wb') as file:
            file.write(decrypted_data)
            logger.info(f"File received successfully: {filename}")
            
    except ValueError as e:
        logger.error(f"Decryption/Verification failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Error receiving file: {e}")
        raise
    finally:
        client_socket.close()
        receiver_socket.close()
