from flask import Flask, request, jsonify, send_file
import base64
import secrets
import time
import io
import json
import numpy as np
from cryptography.hazmat.backends import default_backend
from algorithms import aes, symmetric, classical, ecc
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# ==================== SIMULATION FUNCTIONS ====================

def simulate_aes_gcm(plaintext_bytes, key, iv):
    """Simulate AES-GCM encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Convert plaintext to bytes',
        'data': {
            'plaintext_hex': plaintext_bytes.hex(),
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Key & IV Setup',
        'description': 'Generate 256-bit key and 96-bit IV (nonce)',
        'data': {
            'key_hex': key.hex(), 'key_bits': len(key) * 8,
            'iv_hex': iv.hex(), 'iv_bits': len(iv) * 8
        }
    })
    
    block_count = (len(plaintext_bytes) + 15) // 16
    steps.append({
        'step': 3, 'name': 'Block Division',
        'description': 'Divide plaintext into 16-byte AES blocks',
        'data': {
            'block_size': 16, 'total_blocks': block_count,
            'last_block_size': len(plaintext_bytes) % 16 or 16
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Cipher Initialization',
        'description': 'Initialize AES-256-GCM cipher with key and IV',
        'data': {
            'algorithm': 'AES-256-GCM', 'mode': 'Galois/Counter Mode',
            'authenticated': 'True'
        }
    })
    
    start_time = time.time()
    encrypted_data, tag = aes.encrypt_gcm(plaintext_bytes, key, iv)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Encryption Process',
        'description': 'Encrypt data and generate authentication tag',
        'data': {
            'ciphertext_hex': encrypted_data.hex(),
            'ciphertext_length': len(encrypted_data),
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    steps.append({
        'step': 6, 'name': 'Authentication Tag',
        'description': 'Generate 128-bit authentication tag for integrity',
        'data': {
            'tag_hex': tag.hex(), 'tag_bits': len(tag) * 8,
            'purpose': 'Ensures data integrity and authenticity'
        }
    })
    
    return {'steps': steps, 'encrypt_time': float(encrypt_time)}


def simulate_rsa(plaintext_bytes):
    """Simulate RSA-OAEP encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Validation',
        'description': 'Verify plaintext size for RSA-2048',
        'data': {
            'plaintext_length': len(plaintext_bytes), 'max_allowed': 190,
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else ''),
            'size_check': 'Valid' if len(plaintext_bytes) <= 190 else 'Too large'
        }
    })
    
    if len(plaintext_bytes) > 190:
        return {'steps': steps, 'error': f'RSA can encrypt max 190 bytes, got {len(plaintext_bytes)}'}
    
    keygen_start = time.time()
    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    public_key = private_key.public_key()
    keygen_time = (time.time() - keygen_start) * 1000
    
    steps.append({
        'step': 2, 'name': 'RSA Key Pair Generation',
        'description': 'Generate 2048-bit RSA public/private key pair',
        'data': {
            'key_size': '2048 bits', 'public_exponent': '65537',
            'generation_time_ms': f"{keygen_time:.2f}", 'key_type': 'RSA-2048'
        }
    })
    
    steps.append({
        'step': 3, 'name': 'OAEP Padding Setup',
        'description': 'Configure Optimal Asymmetric Encryption Padding',
        'data': {
            'padding_scheme': 'OAEP', 'hash_algorithm': 'SHA-256',
            'mgf': 'MGF1 with SHA-256', 'label': 'None'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Apply OAEP Padding',
        'description': 'Add randomized padding to plaintext',
        'data': {
            'original_size': len(plaintext_bytes), 'padded_size': 256,
            'padding_overhead': 256 - len(plaintext_bytes),
            'randomized': 'Yes (secure padding)'
        }
    })
    
    encrypt_start = time.time()
    encrypted_data = public_key.encrypt(plaintext_bytes, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    ))
    encrypt_time = (time.time() - encrypt_start) * 1000
    
    steps.append({
        'step': 5, 'name': 'RSA Encryption',
        'description': 'Encrypt padded data using public key',
        'data': {
            'encryption_time_ms': f"{encrypt_time:.2f}",
            'ciphertext_length': len(encrypted_data),
            'ciphertext_preview': encrypted_data[:32].hex() + '...'
        }
    })
    
    decrypt_start = time.time()
    decrypted_data = private_key.decrypt(encrypted_data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    ))
    decrypt_time = (time.time() - decrypt_start) * 1000
    
    steps.append({
        'step': 6, 'name': 'Decryption Verification',
        'description': 'Decrypt with private key to verify',
        'data': {
            'decryption_time_ms': f"{decrypt_time:.2f}",
            'verification': 'Success' if decrypted_data == plaintext_bytes else 'Failed',
            'decrypted_length': len(decrypted_data)
        }
    })
    
    return {
        'steps': steps, 'keygen_time': float(keygen_time),
        'encrypt_time': float(encrypt_time), 'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8')
    }


def simulate_des(plaintext_bytes, key, iv):
    """Simulate DES encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for DES encryption',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Key Setup',
        'description': 'DES uses 56-bit effective key (8 bytes)',
        'data': {
            'key_hex': key.hex(),
            'key_size': '64 bits (56 effective)',
            'iv_hex': iv.hex()
        }
    })
    
    steps.append({
        'step': 3, 'name': 'PKCS7 Padding',
        'description': 'Add padding to make length multiple of 8',
        'data': {
            'block_size': 8,
            'padding_needed': 8 - (len(plaintext_bytes) % 8) if len(plaintext_bytes) % 8 != 0 else 8
        }
    })
    
    start_time = time.time()
    ciphertext = symmetric.encrypt_des(plaintext_bytes, key, iv)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 4, 'name': 'DES Encryption',
        'description': 'Apply 16 rounds of Feistel network',
        'data': {
            'rounds': '16',
            'ciphertext_length': len(ciphertext),
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    steps.append({
        'step': 5, 'name': 'Output',
        'description': 'Encrypted ciphertext ready',
        'data': {
            'ciphertext_preview': ciphertext[:32].hex() + ('...' if len(ciphertext) > 32 else '')
        }
    })
    
    return {'steps': steps, 'encrypt_time': float(encrypt_time)}


def simulate_3des(plaintext_bytes, key, iv):
    """Simulate 3DES encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for 3DES encryption',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Triple Key Setup',
        'description': '3DES uses three 56-bit keys (24 bytes total)',
        'data': {
            'key_hex': key.hex(),
            'key_size': '192 bits (168 effective)',
            'iv_hex': iv.hex(),
            'keys': '3 independent keys'
        }
    })
    
    steps.append({
        'step': 3, 'name': 'PKCS7 Padding',
        'description': 'Add padding to make length multiple of 8',
        'data': {
            'block_size': 8,
            'padding_needed': 8 - (len(plaintext_bytes) % 8) if len(plaintext_bytes) % 8 != 0 else 8
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Triple Encryption',
        'description': 'Encrypt -> Decrypt -> Encrypt (EDE mode)',
        'data': {
            'operation': 'Encrypt with K1, Decrypt with K2, Encrypt with K3',
            'mode': 'EDE (Encrypt-Decrypt-Encrypt)'
        }
    })
    
    start_time = time.time()
    ciphertext = symmetric.encrypt_3des(plaintext_bytes, key, iv)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Output',
        'description': 'Triple-encrypted ciphertext ready',
        'data': {
            'ciphertext_length': len(ciphertext),
            'time_ms': f"{encrypt_time:.4f}",
            'ciphertext_preview': ciphertext[:32].hex() + ('...' if len(ciphertext) > 32 else '')
        }
    })
    
    return {'steps': steps, 'encrypt_time': float(encrypt_time)}


def simulate_blowfish(plaintext_bytes, key, iv):
    """Simulate Blowfish encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for Blowfish encryption',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Key Setup',
        'description': 'Blowfish supports variable key length (4-56 bytes)',
        'data': {
            'key_hex': key.hex(),
            'key_size_bytes': len(key),
            'key_size_bits': len(key) * 8,
            'iv_hex': iv.hex()
        }
    })
    
    steps.append({
        'step': 3, 'name': 'Subkey Generation',
        'description': 'Generate P-array and S-boxes from key',
        'data': {
            'p_array_size': '18 x 32-bit',
            's_boxes': '4 S-boxes, 256 entries each',
            'total_subkeys': '1042'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'PKCS7 Padding',
        'description': 'Add padding to make length multiple of 8',
        'data': {
            'block_size': 8,
            'padding_needed': 8 - (len(plaintext_bytes) % 8) if len(plaintext_bytes) % 8 != 0 else 8
        }
    })
    
    start_time = time.time()
    ciphertext = symmetric.encrypt_blowfish(plaintext_bytes, key, iv)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Feistel Encryption',
        'description': 'Apply 16 rounds of Feistel network',
        'data': {
            'rounds': '16',
            'ciphertext_length': len(ciphertext),
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    steps.append({
        'step': 6, 'name': 'Output',
        'description': 'Blowfish encrypted ciphertext ready',
        'data': {
            'ciphertext_preview': ciphertext[:32].hex() + ('...' if len(ciphertext) > 32 else '')
        }
    })
    
    return {'steps': steps, 'encrypt_time': float(encrypt_time)}


def simulate_chacha20(plaintext_bytes, key, nonce):
    """Simulate ChaCha20 encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for ChaCha20 stream cipher',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Key & Nonce Setup',
        'description': 'ChaCha20 uses 256-bit key and 128-bit nonce',
        'data': {
            'key_hex': key.hex(),
            'key_bits': len(key) * 8,
            'nonce_hex': nonce.hex(),
            'nonce_bits': len(nonce) * 8
        }
    })
    
    steps.append({
        'step': 3, 'name': 'State Initialization',
        'description': 'Initialize 512-bit ChaCha20 state',
        'data': {
            'state_size': '512 bits (16 words x 32 bits)',
            'constants': '"expand 32-byte k" magic constants',
            'counter_init': '0'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Quarter Round Function',
        'description': 'ChaCha20 uses quarter-round mixing function',
        'data': {
            'operations': 'ADD, XOR, ROTATE',
            'rounds': '20 (10 column rounds + 10 diagonal rounds)'
        }
    })
    
    start_time = time.time()
    ciphertext = symmetric.encrypt_chacha20(plaintext_bytes, key, nonce)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Keystream Generation',
        'description': 'Generate keystream and XOR with plaintext',
        'data': {
            'cipher type': 'Stream cipher',
            'operation': 'XOR plaintext with keystream',
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    steps.append({
        'step': 6, 'name': 'Output',
        'description': 'ChaCha20 encrypted ciphertext ready',
        'data': {
            'ciphertext_length': len(ciphertext),
            'ciphertext_preview': ciphertext[:32].hex() + ('...' if len(ciphertext) > 32 else ''),
            'note': 'No padding needed (stream cipher)'
        }
    })
    
    return {'steps': steps, 'encrypt_time': float(encrypt_time)}


def simulate_playfair(plaintext_str, key_str):
    """Simulate Playfair cipher step by step"""
    steps = []
    
    cipher = classical.PlayfairCipher(key_str)
    
    steps.append({
        'step': 1, 'name': 'Key Matrix Generation',
        'description': 'Create 5x5 Playfair matrix from keyword',
        'data': {
            'keyword': key_str.upper(),
            'matrix': [' '.join(row) for row in cipher.matrix],
            'note': 'J is combined with I'
        }
    })
    
    prepared = cipher._prepare_text(plaintext_str)
    steps.append({
        'step': 2, 'name': 'Text Preparation',
        'description': 'Prepare plaintext into digraphs',
        'data': {
            'original': plaintext_str,
            'prepared': ' '.join([prepared[i:i+2] for i in range(0, len(prepared), 2)]),
            'note': 'X inserted between duplicate letters'
        }
    })
    
    steps.append({
        'step': 3, 'name': 'Digraph Rules',
        'description': 'Apply Playfair encryption rules',
        'data': {
            'rule_1': 'Same row: shift right',
            'rule_2': 'Same column: shift down',
            'rule_3': 'Rectangle: swap columns'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 4, 'name': 'Encryption Complete',
        'description': 'Each digraph encrypted using matrix',
        'data': {
            'ciphertext': ' '.join([ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]),
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext}


def simulate_hill(plaintext_str, key_matrix):
    """Simulate Hill cipher step by step"""
    steps = []
    
    cipher = classical.HillCipher(key_matrix)
    
    steps.append({
        'step': 1, 'name': 'Key Matrix Setup',
        'description': 'Initialize 2x2 Hill cipher key matrix',
        'data': {
            'matrix': str(key_matrix),
            'determinant': str(int(np.linalg.det(np.array(key_matrix))) % 26),
            'coprime_check': 'Valid (coprime with 26)'
        }
    })
    
    numbers = cipher._text_to_numbers(plaintext_str)
    steps.append({
        'step': 2, 'name': 'Text to Numbers',
        'description': 'Convert letters to numbers (A=0, B=1, ...)',
        'data': {
            'plaintext': plaintext_str.upper(),
            'numbers': str(numbers)
        }
    })
    
    steps.append({
        'step': 3, 'name': 'Matrix Multiplication',
        'description': 'Multiply key matrix with plaintext vectors',
        'data': {
            'operation': 'C = K × P (mod 26)',
            'vector_size': '2x1',
            'modulus': '26'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 4, 'name': 'Encryption Complete',
        'description': 'Numbers converted back to letters',
        'data': {
            'ciphertext': ciphertext,
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext}


def simulate_vigenere(plaintext_str, key_str):
    """Simulate Vigenère cipher step by step"""
    steps = []
    
    cipher = classical.VigenereCipher(key_str)
    
    steps.append({
        'step': 1, 'name': 'Keyword Setup',
        'description': 'Prepare encryption keyword',
        'data': {
            'keyword': cipher.key,
            'key_length': len(cipher.key)
        }
    })
    
    # Show first few shifts
    shifts = [ord(c) - ord('A') for c in cipher.key[:5]]
    steps.append({
        'step': 2, 'name': 'Calculate Shifts',
        'description': 'Each keyword letter determines shift amount',
        'data': {
            'first_5_letters': cipher.key[:5],
            'first_5_shifts': str(shifts),
            'note': 'Shift repeats for entire plaintext'
        }
    })
    
    steps.append({
        'step': 3, 'name': 'Caesar Shift Application',
        'description': 'Apply Caesar cipher with varying shifts',
        'data': {
            'method': 'C[i] = (P[i] + K[i mod keylen]) mod 26',
            'polyalphabetic': 'Yes'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 4, 'name': 'Encryption Complete',
        'description': 'All characters shifted according to keyword',
        'data': {
            'ciphertext': ciphertext,
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext}


def simulate_railfence(plaintext_str, rails1, rails2):
    """Simulate Double Rail Fence cipher step by step"""
    steps = []
    
    cipher = classical.DoubleRailFenceCipher(rails1, rails2)
    
    steps.append({
        'step': 1, 'name': 'Configuration',
        'description': 'Set up double rail fence parameters',
        'data': {
            'first_pass_rails': rails1,
            'second_pass_rails': rails2,
            'plaintext_length': len(plaintext_str)
        }
    })
    
    steps.append({
        'step': 2, 'name': 'First Rail Fence Pass',
        'description': f'Write plaintext in zigzag pattern across {rails1} rails',
        'data': {
            'rails': rails1,
            'pattern': 'Zigzag down and up'
        }
    })
    
    # Do first pass manually for visualization
    temp = cipher._rail_fence_encrypt(plaintext_str.replace(' ', ''), rails1)
    
    steps.append({
        'step': 3, 'name': 'First Pass Complete',
        'description': 'Read rails left-to-right, top-to-bottom',
        'data': {
            'intermediate': temp[:50] + ('...' if len(temp) > 50 else '')
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Second Rail Fence Pass',
        'description': f'Apply rail fence again with {rails2} rails',
        'data': {
            'rails': rails2,
            'pattern': 'Zigzag down and up on intermediate text'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 5, 'name': 'Encryption Complete',
        'description': 'Double transposition complete',
        'data': {
            'ciphertext': ciphertext,
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext}


def simulate_columnar(plaintext_str, key1, key2):
    """Simulate Double Columnar Transposition cipher step by step"""
    steps = []
    
    cipher = classical.DoubleColumnarTransposition(key1, key2)
    
    steps.append({
        'step': 1, 'name': 'Keyword Setup',
        'description': 'Prepare transposition keywords',
        'data': {
            'first_key': key1.upper(),
            'second_key': key2.upper(),
            'first_columns': len(key1),
            'second_columns': len(key2)
        }
    })
    
    steps.append({
        'step': 2, 'name': 'Column Order Calculation',
        'description': 'Determine column reading order alphabetically',
        'data': {
            'first_order': str(cipher.order1),
            'second_order': str(cipher.order2)
        }
    })
    
    steps.append({
        'step': 3, 'name': 'First Transposition',
        'description': 'Write plaintext in grid, read by column order',
        'data': {
            'method': 'Write row-by-row, read column-by-column'
        }
    })
    
    # Do first pass
    temp = cipher._columnar_encrypt(plaintext_str.replace(' ', '').upper(), cipher.order1, len(key1))
    
    steps.append({
        'step': 4, 'name': 'First Pass Complete',
        'description': 'Intermediate ciphertext from first transposition',
        'data': {
            'intermediate': temp[:50] + ('...' if len(temp) > 50 else '')
        }
    })
    
    steps.append({
        'step': 5, 'name': 'Second Transposition',
        'description': 'Apply columnar transposition again with second key',
        'data': {
            'method': 'Transpose intermediate text with second key'
        }
    })
    
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext_str)
    encrypt_time = (time.time() - start_time) * 1000
    
    steps.append({
        'step': 6, 'name': 'Encryption Complete',
        'description': 'Double columnar transposition complete',
        'data': {
            'ciphertext': ciphertext,
            'time_ms': f"{encrypt_time:.4f}"
        }
    })
    
    return {'steps': steps, 'ciphertext': ciphertext}


def simulate_ecc(plaintext_bytes):
    """Simulate ECC (ECIES) encryption step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Prepare plaintext for ECC encryption',
        'data': {
            'plaintext_length': len(plaintext_bytes),
            'plaintext_preview': plaintext_bytes[:32].hex() + ('...' if len(plaintext_bytes) > 32 else '')
        }
    })
    
    keygen_start = time.time()
    private_key, public_key = ecc.generate_ecc_keypair()
    keygen_time = (time.time() - keygen_start) * 1000
    
    steps.append({
        'step': 2, 'name': 'ECC Key Pair Generation',
        'description': 'Generate elliptic curve key pair (secp256r1)',
        'data': {
            'curve': 'secp256r1 (NIST P-256)',
            'key_size': '256 bits',
            'generation_time_ms': f"{keygen_time:.2f}"
        }
    })
    
    steps.append({
        'step': 3, 'name': 'ECIES Protocol',
        'description': 'Use Elliptic Curve Integrated Encryption Scheme',
        'data': {
            'protocol': 'ECIES',
            'components': 'ECDH + KDF + AES-GCM'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Ephemeral Key Generation',
        'description': 'Generate temporary key pair for this message',
        'data': {
            'purpose': 'One-time key for ECDH',
            'security': 'Perfect forward secrecy'
        }
    })
    
    steps.append({
        'step': 5, 'name': 'Shared Secret Derivation',
        'description': 'Perform ECDH to get shared secret',
        'data': {
            'method': 'Ephemeral private × Recipient public',
            'kdf': 'HKDF-SHA256 for key derivation'
        }
    })
    
    encrypt_start = time.time()
    encrypted_data = ecc.encrypt_ecc(plaintext_bytes, public_key)
    encrypt_time = (time.time() - encrypt_start) * 1000
    
    steps.append({
        'step': 6, 'name': 'AES-GCM Encryption',
        'description': 'Encrypt plaintext with derived key using AES-GCM',
        'data': {
            'cipher': 'AES-256-GCM',
            'ciphertext_length': len(encrypted_data['ciphertext']),
            'time_ms': f"{encrypt_time:.2f}"
        }
    })
    
    steps.append({
        'step': 7, 'name': 'Output Components',
        'description': 'ECIES output includes multiple components',
        'data': {
            'ephemeral_public_key': encrypted_data['ephemeral_public_key'][:16].hex() + '...',
            'iv_length': len(encrypted_data['iv']),
            'tag_length': len(encrypted_data['tag']),
            'total_overhead': len(encrypted_data['ephemeral_public_key']) + len(encrypted_data['iv']) + len(encrypted_data['tag'])
        }
    })
    
    return {
        'steps': steps,
        'keygen_time': float(keygen_time),
        'encrypt_time': float(encrypt_time),
        'private_key': private_key,
        'encrypted_data': encrypted_data
    }


# ==================== API ENDPOINTS ====================

@app.route('/')
def index():
    return send_file('crypto_frontend.html')


# AES endpoint
@app.route('/api/aes', methods=['POST'])
def aes_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        
        start_time = time.time()
        ciphertext, tag = aes.encrypt_gcm(input_bytes, key, iv)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(ciphertext),
            'iv': iv.hex(),
            'tag': tag.hex(),
            'key': key.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/aes-simulate', methods=['POST'])
def aes_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        
        result = simulate_aes_gcm(input_bytes, key, iv)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# RSA endpoint
@app.route('/api/rsa', methods=['POST'])
def rsa_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        if len(input_bytes) > 190:
            raise Exception(f"RSA max 190 bytes. Input: {len(input_bytes)} bytes")
        
        keygen_start = time.time()
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        public_key = private_key.public_key()
        keygen_time = (time.time() - keygen_start) * 1000
        
        encrypted_data = public_key.encrypt(input_bytes, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        ))
        
        return jsonify({
            'success': True,
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(encrypted_data),
            'keygenTime': f"{keygen_time:.0f}",
            'encrypted': base64.b64encode(encrypted_data).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/rsa-simulate', methods=['POST'])
def rsa_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        result = simulate_rsa(input_bytes)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# DES endpoints
@app.route('/api/des', methods=['POST'])
def des_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_des_key()
        iv = secrets.token_bytes(8)
        
        start_time = time.time()
        ciphertext = symmetric.encrypt_des(input_bytes, key, iv)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'DES',
            'originalName': data['name'],
            'original Size': data['size'],
            'encryptedSize': len(ciphertext),
            'key': key.hex(),
            'iv': iv.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/des-simulate', methods=['POST'])
def des_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_des_key()
        iv = secrets.token_bytes(8)
        
        result = simulate_des(input_bytes, key, iv)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# 3DES endpoints
@app.route('/api/3des', methods=['POST'])
def des3_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_3des_key()
        iv = secrets.token_bytes(8)
        
        start_time = time.time()
        ciphertext = symmetric.encrypt_3des(input_bytes, key, iv)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': '3DES',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(ciphertext),
            'key': key.hex(),
            'iv': iv.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/3des-simulate', methods=['POST'])
def des3_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_3des_key()
        iv = secrets.token_bytes(8)
        
        result = simulate_3des(input_bytes, key, iv)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Blowfish endpoints
@app.route('/api/blowfish', methods=['POST'])
def blowfish_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_blowfish_key(16)
        iv = secrets.token_bytes(8)
        
        start_time = time.time()
        ciphertext = symmetric.encrypt_blowfish(input_bytes, key, iv)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Blowfish',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(ciphertext),
            'key': key.hex(),
            'iv': iv.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/blowfish-simulate', methods=['POST'])
def blowfish_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_blowfish_key(16)
        iv = secrets.token_bytes(8)
        
        result = simulate_blowfish(input_bytes, key, iv)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ChaCha20 endpoints
@app.route('/api/chacha20', methods=['POST'])
def chacha20_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_chacha20_key()
        nonce = symmetric.generate_chacha20_nonce()
        
        start_time = time.time()
        ciphertext = symmetric.encrypt_chacha20(input_bytes, key, nonce)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'ChaCha20',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(ciphertext),
            'key': key.hex(),
            'nonce': nonce.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': base64.b64encode(ciphertext).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/chacha20-simulate', methods=['POST'])
def chacha20_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key = symmetric.generate_chacha20_key()
        nonce = symmetric.generate_chacha20_nonce()
        
        result = simulate_chacha20(input_bytes, key, nonce)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Playfair endpoints
@app.route('/api/playfair', methods=['POST'])
def playfair_endpoint():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64decode(data['data']).decode('utf-8')
        key = data.get('key', 'KEYWORD')
        
        cipher = classical.PlayfairCipher(key)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Playfair',
            'originalName': data['name'],
            'key': key,
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/playfair-simulate', methods=['POST'])
def playfair_simulate():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64decode(data['data']).decode('utf-8')
        key = data.get('key', 'KEYWORD')
        
        result = simulate_playfair(plaintext, key)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Hill endpoints
@app.route('/api/hill', methods=['POST'])
def hill_endpoint():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64decode(data['data']).decode('utf-8')
        key_matrix = data.get('keyMatrix', [[3, 3], [2, 5]])
        
        cipher = classical.HillCipher(key_matrix)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Hill',
            'originalName': data['name'],
            'keyMatrix': key_matrix,
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/hill-simulate', methods=['POST'])
def hill_simulate():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64decode(data['data']).decode('utf-8')
        key_matrix = data.get('keyMatrix', [[3, 3], [2, 5]])
        
        result = simulate_hill(plaintext, key_matrix)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Vigenère endpoints
@app.route('/api/vigenere', methods=['POST'])
def vigenere_endpoint():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64decode(data['data']).decode('utf-8')
        key = data.get('key', 'SECRET')
        
        cipher = classical.VigenereCipher(key)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Vigenere',
            'originalName': data['name'],
            'key': key,
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/vigenere-simulate', methods=['POST'])
def vigenere_simulate():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64decode(data['data']).decode('utf-8')
        key = data.get('key', 'SECRET')
        
        result = simulate_vigenere(plaintext, key)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Rail Fence endpoints
@app.route('/api/railfence', methods=['POST'])
def railfence_endpoint():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64decode(data['data']).decode('utf-8')
        rails1 = data.get('rails1', 3)
        rails2 = data.get('rails2', 4)
        
        cipher = classical.DoubleRailFenceCipher(rails1, rails2)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Double Rail Fence',
            'originalName': data['name'],
            'rails1': rails1,
            'rails2': rails2,
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/railfence-simulate', methods=['POST'])
def railfence_simulate():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64encode(data['data']).decode('utf-8')
        rails1 = data.get('rails1', 3)
        rails2 = data.get('rails2', 4)
        
        result = simulate_railfence(plaintext, rails1, rails2)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Columnar endpoints
@app.route('/api/columnar', methods=['POST'])
def columnar_endpoint():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64decode(data['data']).decode('utf-8')
        key1 = data.get('key1', 'HACK')
        key2 = data.get('key2', 'CRYPTO')
        
        cipher = classical.DoubleColumnarTransposition(key1, key2)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'Double Columnar Transposition',
            'originalName': data['name'],
            'key1': key1,
            'key2': key2,
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': ciphertext
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/columnar-simulate', methods=['POST'])
def columnar_simulate():
    try:
        data = request.json
        plaintext = data['data'] if data['type'] == 'text' else base64.b64decode(data['data']).decode('utf-8')
        key1 = data.get('key1', 'HACK')
        key2 = data.get('key2', 'CRYPTO')
        
        result = simulate_columnar(plaintext, key1, key2)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ECC endpoints
@app.route('/api/ecc', methods=['POST'])
def ecc_endpoint():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        private_key, public_key = ecc.generate_ecc_keypair()
        
        start_time = time.time()
        encrypted_data = ecc.encrypt_ecc(input_bytes, public_key)
        encrypt_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': 'ECC (ECIES)',
            'originalName': data['name'],
            'originalSize': data['size'],
            'encryptedSize': len(encrypted_data['ciphertext']),
            'ephemeralPublicKey': encrypted_data['ephemeral_public_key'].hex(),
            'iv': encrypted_data['iv'].hex(),
            'tag': encrypted_data['tag'].hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': base64.b64encode(encrypted_data['ciphertext']).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/ecc-simulate', methods=['POST'])
def ecc_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        result = simulate_ecc(input_bytes)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Decryption endpoints
@app.route('/api/decrypt', methods=['POST'])
def decrypt_endpoint():
    try:
        data = request.json
        algorithm = data['algorithm']
        
        if algorithm == 'AES':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            iv = bytes.fromhex(data['iv'])
            tag = bytes.fromhex(data['tag'])
            
            plaintext = aes.decrypt_gcm(ciphertext, key, iv, tag)
            
        elif algorithm == 'DES':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            iv = bytes.fromhex(data['iv'])
            
            plaintext = symmetric.decrypt_des(ciphertext, key, iv)
            
        elif algorithm == '3DES':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            iv = bytes.fromhex(data['iv'])
            
            plaintext = symmetric.decrypt_3des(ciphertext, key, iv)
            
        elif algorithm == 'Blowfish':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            iv = bytes.fromhex(data['iv'])
            
            plaintext = symmetric.decrypt_blowfish(ciphertext, key, iv)
            
        elif algorithm == 'ChaCha20':
            ciphertext = base64.b64decode(data['ciphertext'])
            key = bytes.fromhex(data['key'])
            nonce = bytes.fromhex(data['nonce'])
            
            plaintext = symmetric.decrypt_chacha20(ciphertext, key, nonce)
            
        elif algorithm == 'Playfair':
            ciphertext = data['ciphertext']
            key = data['key']
            
            cipher = classical.PlayfairCipher(key)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        elif algorithm == 'Hill':
            ciphertext = data['ciphertext']
            key_matrix = data['keyMatrix']
            
            cipher = classical.HillCipher(key_matrix)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        elif algorithm == 'Vigenere':
            ciphertext = data['ciphertext']
            key = data['key']
            
            cipher = classical.VigenereCipher(key)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        elif algorithm == 'Double Rail Fence':
            ciphertext = data['ciphertext']
            rails1 = data['rails1']
            rails2 = data['rails2']
            
            cipher = classical.DoubleRailFenceCipher(rails1, rails2)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        elif algorithm == 'Double Columnar Transposition':
            ciphertext = data['ciphertext']
            key1 = data['key1']
            key2 = data['key2']
            
            cipher = classical.DoubleColumnarTransposition(key1, key2)
            plaintext = cipher.decrypt(ciphertext).encode('utf-8')
            
        else:
            return jsonify({'success': False, 'error': f'Unknown algorithm: {algorithm}'})
        
        # Try to decode as text
        try:
            plaintext_text = plaintext.decode('utf-8')
            is_text = True
        except:
            plaintext_text = base64.b64encode(plaintext).decode('utf-8')
            is_text = False
        
        return jsonify({
            'success': True,
            'plaintext': plaintext_text,
            'isText': is_text,
            'size': len(plaintext)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


if __name__ == '__main__':
    print("🔐 Crypto Tool Server Starting...")
    print("Open: http://localhost:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
