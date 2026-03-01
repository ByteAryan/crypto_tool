"""
Elliptic Curve Cryptography (ECC) for encryption/decryption
Uses ECIES (Elliptic Curve Integrated Encryption Scheme)
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os


def generate_ecc_keypair() -> tuple:
    """Generate ECC key pair using secp256r1 curve.
    
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_ecc(plaintext: bytes, public_key) -> dict:
    """Encrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme).
    
    Args:
        plaintext: Data to encrypt
        public_key: Recipient's EC public key
    
    Returns:
        dict: Contains ephemeral_public_key, ciphertext, and tag
    """
    # Generate ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # Perform ECDH to get shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    
    # Derive encryption key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption',
        backend=default_backend()
    ).derive(shared_secret)
    
    # Generate IV for AES-GCM
    iv = os.urandom(12)
    
    # Encrypt using AES-GCM
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Serialize ephemeral public key
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return {
        'ephemeral_public_key': ephemeral_public_bytes,
        'iv': iv,
        'ciphertext': ciphertext,
        'tag': encryptor.tag
    }


def decrypt_ecc(encrypted_data: dict, private_key) -> bytes:
    """Decrypt ECIES encrypted data.
    
    Args:
        encrypted_data: Dictionary containing ephemeral_public_key, iv, ciphertext, and tag
        private_key: Recipient's EC private key
    
    Returns:
        bytes: Decrypted plaintext
    """
    # Reconstruct ephemeral public key
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        encrypted_data['ephemeral_public_key']
    )
    
    # Perform ECDH to get shared secret
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    
    # Derive decryption key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption',
        backend=default_backend()
    ).derive(shared_secret)
    
    # Decrypt using AES-GCM
    cipher = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(encrypted_data['iv'], encrypted_data['tag']),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
    
    return plaintext


def serialize_public_key(public_key) -> bytes:
    """Serialize EC public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def serialize_private_key(private_key) -> bytes:
    """Serialize EC private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def deserialize_public_key(pem_bytes: bytes):
    """Deserialize EC public key from PEM format."""
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())


def deserialize_private_key(pem_bytes: bytes):
    """Deserialize EC private key from PEM format."""
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None,
        backend=default_backend()
    )
