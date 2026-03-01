"""File encryption and decryption utilities for cross-platform use."""
import os
import json
import base64
from typing import Tuple, Optional
from algorithms import aes
from utils import key_generator, file_handler


class FileEncryptionResult:
    """Container for file encryption results."""
    def __init__(self, ciphertext: bytes, key: bytes, iv: bytes, 
                 tag: Optional[bytes] = None, mode: str = 'CBC'):
        self.ciphertext = ciphertext
        self.key = key
        self.iv = iv
        self.tag = tag
        self.mode = mode
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        result = {
            'ciphertext': base64.b64encode(self.ciphertext).decode('utf-8'),
            'key': self.key.hex(),
            'iv': self.iv.hex(),
            'mode': self.mode,
            'algorithm': 'AES-256'
        }
        if self.tag:
            result['tag'] = self.tag.hex()
        return result
    
    def save_to_file(self, output_path: str):
        """Save encryption result to a JSON file."""
        output_path = os.path.normpath(output_path)
        with open(output_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


def encrypt_file_cbc(input_path: str, output_path: Optional[str] = None, 
                     key: Optional[bytes] = None, iv: Optional[bytes] = None) -> FileEncryptionResult:
    """
    Encrypt a file using AES-256-CBC mode.
    
    Args:
        input_path: Path to the file to encrypt
        output_path: Optional path to save encrypted file (defaults to input_path.enc)
        key: Optional encryption key (generates new one if not provided)
        iv: Optional initialization vector (generates new one if not provided)
    
    Returns:
        FileEncryptionResult object containing encryption details
    """
    # Normalize paths for cross-platform compatibility
    input_path = os.path.normpath(input_path)
    
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    # Generate key and IV if not provided
    if key is None:
        key = key_generator.generate_aes_key(32)  # 256-bit key
    if iv is None:
        iv = key_generator.generate_iv(16)  # 128-bit IV for CBC
    
    # Read and encrypt file
    plaintext = file_handler.read_file_bytes(input_path)
    ciphertext = aes.encrypt(plaintext, key, iv)
    
    # Create result
    result = FileEncryptionResult(ciphertext, key, iv, mode='CBC')
    
    # Save encrypted file if output path provided
    if output_path:
        output_path = os.path.normpath(output_path)
        result.save_to_file(output_path)
    
    return result


def encrypt_file_gcm(input_path: str, output_path: Optional[str] = None,
                     key: Optional[bytes] = None, iv: Optional[bytes] = None) -> FileEncryptionResult:
    """
    Encrypt a file using AES-256-GCM mode (authenticated encryption).
    
    Args:
        input_path: Path to the file to encrypt
        output_path: Optional path to save encrypted file (defaults to input_path.enc)
        key: Optional encryption key (generates new one if not provided)
        iv: Optional initialization vector (generates new one if not provided)
    
    Returns:
        FileEncryptionResult object containing encryption details
    """
    # Normalize paths for cross-platform compatibility
    input_path = os.path.normpath(input_path)
    
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    # Generate key and IV if not provided
    if key is None:
        key = key_generator.generate_aes_key(32)  # 256-bit key
    if iv is None:
        iv = key_generator.generate_iv(12)  # 96-bit IV for GCM (recommended)
    
    # Read and encrypt file
    plaintext = file_handler.read_file_bytes(input_path)
    ciphertext, tag = aes.encrypt_gcm(plaintext, key, iv)
    
    # Create result
    result = FileEncryptionResult(ciphertext, key, iv, tag=tag, mode='GCM')
    
    # Save encrypted file if output path provided
    if output_path:
        output_path = os.path.normpath(output_path)
        result.save_to_file(output_path)
    
    return result


def decrypt_file_from_json(encrypted_file_path: str, output_path: Optional[str] = None) -> bytes:
    """
    Decrypt a file from a JSON encryption result file.
    
    Args:
        encrypted_file_path: Path to the JSON file containing encryption details
        output_path: Optional path to save decrypted file
    
    Returns:
        Decrypted plaintext bytes
    """
    # Normalize path for cross-platform compatibility
    encrypted_file_path = os.path.normpath(encrypted_file_path)
    
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")
    
    # Load encryption details
    with open(encrypted_file_path, 'r') as f:
        data = json.load(f)
    
    # Extract encryption parameters
    ciphertext = base64.b64decode(data['ciphertext'])
    key = bytes.fromhex(data['key'])
    iv = bytes.fromhex(data['iv'])
    mode = data.get('mode', 'CBC')
    
    # Decrypt based on mode
    if mode == 'GCM':
        tag = bytes.fromhex(data['tag'])
        plaintext = aes.decrypt_gcm(ciphertext, key, iv, tag)
    else:  # CBC
        plaintext = aes.decrypt(ciphertext, key, iv)
    
    # Save decrypted file if output path provided
    if output_path:
        output_path = os.path.normpath(output_path)
        file_handler.write_file_bytes(output_path, plaintext)
    
    return plaintext


def decrypt_file_cbc(ciphertext: bytes, key: bytes, iv: bytes, 
                     output_path: Optional[str] = None) -> bytes:
    """
    Decrypt data using AES-256-CBC mode.
    
    Args:
        ciphertext: Encrypted data
        key: Decryption key
        iv: Initialization vector
        output_path: Optional path to save decrypted file
    
    Returns:
        Decrypted plaintext bytes
    """
    plaintext = aes.decrypt(ciphertext, key, iv)
    
    if output_path:
        output_path = os.path.normpath(output_path)
        file_handler.write_file_bytes(output_path, plaintext)
    
    return plaintext


def decrypt_file_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes,
                     output_path: Optional[str] = None) -> bytes:
    """
    Decrypt data using AES-256-GCM mode.
    
    Args:
        ciphertext: Encrypted data
        key: Decryption key
        iv: Initialization vector
        tag: Authentication tag
        output_path: Optional path to save decrypted file
    
    Returns:
        Decrypted plaintext bytes
    """
    plaintext = aes.decrypt_gcm(ciphertext, key, iv, tag)
    
    if output_path:
        output_path = os.path.normpath(output_path)
        file_handler.write_file_bytes(output_path, plaintext)
    
    return plaintext
