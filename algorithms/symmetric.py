"""
Modern symmetric encryption algorithms: DES, 3DES, Blowfish, ChaCha20
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def encrypt_des(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt data using DES with CBC mode and PKCS7 padding.
    
    Args:
        plaintext: Data to encrypt
        key: 8-byte DES key
        iv: 8-byte initialization vector
    
    Returns:
        Encrypted ciphertext
    """
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    if len(iv) != 8:
        raise ValueError("DES IV must be 8 bytes")
    
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 padding for 8-byte blocks
    padding_len = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([padding_len]) * padding_len
    
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_des(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt DES encrypted data and validate PKCS7 padding.
    
    Args:
        ciphertext: Data to decrypt
        key: 8-byte DES key
        iv: 8-byte initialization vector
    
    Returns:
        Decrypted plaintext
    """
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    if len(iv) != 8:
        raise ValueError("DES IV must be 8 bytes")
    
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Validate padding
    if len(padded) == 0:
        raise ValueError("Invalid ciphertext: empty result")
    
    padding_len = padded[-1]
    if padding_len < 1 or padding_len > 8:
        raise ValueError("Invalid padding length")
    
    for i in range(padding_len):
        if padded[-(i+1)] != padding_len:
            raise ValueError("Invalid padding bytes")
    
    return padded[:-padding_len]


def encrypt_3des(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt data using 3DES with CBC mode and PKCS7 padding.
    
    Args:
        plaintext: Data to encrypt
        key: 24-byte 3DES key (or 16-byte for two-key 3DES)
        iv: 8-byte initialization vector
    
    Returns:
        Encrypted ciphertext
    """
    if len(key) not in [16, 24]:
        raise ValueError("3DES key must be 16 or 24 bytes")
    if len(iv) != 8:
        raise ValueError("3DES IV must be 8 bytes")
    
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 padding for 8-byte blocks
    padding_len = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([padding_len]) * padding_len
    
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_3des(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt 3DES encrypted data and validate PKCS7 padding.
    
    Args:
        ciphertext: Data to decrypt
        key: 24-byte 3DES key (or 16-byte for two-key 3DES)
        iv: 8-byte initialization vector
    
    Returns:
        Decrypted plaintext
    """
    if len(key) not in [16, 24]:
        raise ValueError("3DES key must be 16 or 24 bytes")
    if len(iv) != 8:
        raise ValueError("3DES IV must be 8 bytes")
    
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Validate padding
    if len(padded) == 0:
        raise ValueError("Invalid ciphertext: empty result")
    
    padding_len = padded[-1]
    if padding_len < 1 or padding_len > 8:
        raise ValueError("Invalid padding length")
    
    for i in range(padding_len):
        if padded[-(i+1)] != padding_len:
            raise ValueError("Invalid padding bytes")
    
    return padded[:-padding_len]


def encrypt_blowfish(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt data using Blowfish with CBC mode and PKCS7 padding.
    
    Args:
        plaintext: Data to encrypt
        key: 4-56 byte Blowfish key
        iv: 8-byte initialization vector
    
    Returns:
        Encrypted ciphertext
    """
    if len(key) < 4 or len(key) > 56:
        raise ValueError("Blowfish key must be between 4 and 56 bytes")
    if len(iv) != 8:
        raise ValueError("Blowfish IV must be 8 bytes")
    
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 padding for 8-byte blocks
    padding_len = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([padding_len]) * padding_len
    
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_blowfish(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt Blowfish encrypted data and validate PKCS7 padding.
    
    Args:
        ciphertext: Data to decrypt
        key: 4-56 byte Blowfish key
        iv: 8-byte initialization vector
    
    Returns:
        Decrypted plaintext
    """
    if len(key) < 4 or len(key) > 56:
        raise ValueError("Blowfish key must be between 4 and 56 bytes")
    if len(iv) != 8:
        raise ValueError("Blowfish IV must be 8 bytes")
    
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Validate padding
    if len(padded) == 0:
        raise ValueError("Invalid ciphertext: empty result")
    
    padding_len = padded[-1]
    if padding_len < 1 or padding_len > 8:
        raise ValueError("Invalid padding length")
    
    for i in range(padding_len):
        if padded[-(i+1)] != padding_len:
            raise ValueError("Invalid padding bytes")
    
    return padded[:-padding_len]


def encrypt_chacha20(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt data using ChaCha20 stream cipher.
    
    Args:
        plaintext: Data to encrypt
        key: 32-byte ChaCha20 key
        nonce: 16-byte nonce
    
    Returns:
        Encrypted ciphertext
    """
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 16:
        raise ValueError("ChaCha20 nonce must be 16 bytes")
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_chacha20(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt ChaCha20 encrypted data.
    
    Args:
        ciphertext: Data to decrypt
        key: 32-byte ChaCha20 key
        nonce: 16-byte nonce
    
    Returns:
        Decrypted plaintext
    """
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 16:
        raise ValueError("ChaCha20 nonce must be 16 bytes")
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def generate_des_key() -> bytes:
    """Generate a random 8-byte DES key."""
    return os.urandom(8)


def generate_3des_key() -> bytes:
    """Generate a random 24-byte 3DES key."""
    return os.urandom(24)


def generate_blowfish_key(size: int = 16) -> bytes:
    """Generate a random Blowfish key (4-56 bytes)."""
    if size < 4 or size > 56:
        raise ValueError("Blowfish key size must be between 4 and 56 bytes")
    return os.urandom(size)


def generate_chacha20_key() -> bytes:
    """Generate a random 32-byte ChaCha20 key."""
    return os.urandom(32)


def generate_chacha20_nonce() -> bytes:
    """Generate a random 16-byte ChaCha20 nonce."""
    return os.urandom(16)
