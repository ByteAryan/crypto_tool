from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt data using AES-CBC with PKCS7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # AES requires padding to 16 bytes (PKCS7 padding)
    padding_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([padding_len]) * padding_len
    return encryptor.update(padded) + encryptor.finalize()

def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data using AES-CBC and validate PKCS7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Validate padding
    if len(padded) == 0:
        raise ValueError("Invalid ciphertext: empty result")
    
    padding_len = padded[-1]
    
    # Validate padding length
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding length")
    
    # Validate all padding bytes
    for i in range(padding_len):
        if padded[-(i+1)] != padding_len:
            raise ValueError("Invalid padding bytes")
    
    return padded[:-padding_len]

def encrypt_gcm(plaintext: bytes, key: bytes, iv: bytes) -> tuple[bytes, bytes]:
    """Encrypt data using AES-GCM (authenticated encryption).
    
    Returns:
        tuple: (ciphertext, authentication_tag)
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag

def decrypt_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    """Decrypt data using AES-GCM and verify authentication tag.
    
    Raises:
        ValueError: If authentication tag verification fails
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
