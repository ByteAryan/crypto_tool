from flask import Flask, request, jsonify
import base64
import hashlib
import secrets
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

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
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    steps.append({
        'step': 4, 'name': 'Cipher Initialization',
        'description': 'Initialize AES-256-GCM cipher with key and IV',
        'data': {
            'algorithm': 'AES-256-GCM', 'mode': 'Galois/Counter Mode',
            'authenticated': str(True)
        }
    })
    
    start_time = time.time()
    encrypted_data = encryptor.update(plaintext_bytes) + encryptor.finalize()
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
    
    tag = encryptor.tag
    steps.append({
        'step': 6, 'name': 'Authentication Tag',
        'description': 'Generate 128-bit authentication tag for integrity',
        'data': {
            'tag_hex': tag.hex(), 'tag_bits': len(tag) * 8,
            'purpose': 'Ensures data integrity and authenticity'
        }
    })
    
    steps.append({
        'step': 7, 'name': 'Final Output',
        'description': 'Combine encrypted data with metadata',
        'data': {
            'output_components': 'IV/Nonce, Ciphertext, Auth Tag',
            'total_output_size': len(iv) + len(encrypted_data) + len(tag),
            'expansion_bytes': (len(iv) + len(encrypted_data) + len(tag)) - len(plaintext_bytes)
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
        raise Exception(f"RSA max 190 bytes. Input: {len(plaintext_bytes)} bytes")
    
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
    
    steps.append({
        'step': 7, 'name': 'RSA Summary',
        'description': 'Complete encryption/decryption cycle',
        'data': {
            'total_keygen_time_ms': f"{keygen_time:.2f}",
            'total_encrypt_time_ms': f"{encrypt_time:.2f}",
            'total_decrypt_time_ms': f"{decrypt_time:.2f}",
            'output_size': len(encrypted_data),
            'security_level': '112-bit equivalent'
        }
    })
    
    return {
        'steps': steps, 'keygen_time': float(keygen_time),
        'encrypt_time': float(encrypt_time), 'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8')
    }

def simulate_ecdh():
    """Simulate ECDH key exchange step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Elliptic Curve Selection',
        'description': 'Select SECP256R1 (P-256) elliptic curve',
        'data': {
            'curve_name': 'SECP256R1 (P-256)', 'curve_type': 'NIST Prime Curve',
            'key_size': '256 bits', 'security_level': '128-bit equivalent'
        }
    })
    
    alice_start = time.time()
    alice_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    alice_public = alice_private.public_key()
    alice_time = (time.time() - alice_start) * 1000
    
    alice_public_bytes = alice_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    steps.append({
        'step': 2, 'name': "Alice's Key Generation",
        'description': 'Generate private/public key pair for Alice',
        'data': {
            'generation_time_ms': f"{alice_time:.4f}", 'private_key_size': '256 bits',
            'public_key_bytes': len(alice_public_bytes),
            'public_key_preview': alice_public_bytes[:16].hex() + '...'
        }
    })
    
    bob_start = time.time()
    bob_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    bob_public = bob_private.public_key()
    bob_time = (time.time() - bob_start) * 1000
    
    bob_public_bytes = bob_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    steps.append({
        'step': 3, 'name': "Bob's Key Generation",
        'description': 'Generate private/public key pair for Bob',
        'data': {
            'generation_time_ms': f"{bob_time:.4f}", 'private_key_size': '256 bits',
            'public_key_bytes': len(bob_public_bytes),
            'public_key_preview': bob_public_bytes[:16].hex() + '...'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Public Key Exchange',
        'description': 'Alice and Bob exchange public keys',
        'data': {
            'alice_sends': f"{alice_public_bytes[:16].hex()}...",
            'bob_sends': f"{bob_public_bytes[:16].hex()}...",
            'exchange_method': 'Unencrypted channel (public keys)',
            'security_note': 'Public keys are safe to transmit'
        }
    })
    
    alice_shared_start = time.time()
    alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
    alice_shared_time = (time.time() - alice_shared_start) * 1000
    
    steps.append({
        'step': 5, 'name': "Alice's Shared Secret",
        'description': 'Alice computes shared secret using her private key and Bob\'s public key',
        'data': {
            'computation_time_ms': f"{alice_shared_time:.4f}",
            'shared_secret_length': len(alice_shared),
            'shared_secret_preview': alice_shared[:16].hex() + '...'
        }
    })
    
    bob_shared_start = time.time()
    bob_shared = bob_private.exchange(ec.ECDH(), alice_public)
    bob_shared_time = (time.time() - bob_shared_start) * 1000
    
    steps.append({
        'step': 6, 'name': "Bob's Shared Secret",
        'description': 'Bob computes shared secret using his private key and Alice\'s public key',
        'data': {
            'computation_time_ms': f"{bob_shared_time:.4f}",
            'shared_secret_length': len(bob_shared),
            'shared_secret_preview': bob_shared[:16].hex() + '...'
        }
    })
    
    agreement = alice_shared == bob_shared
    steps.append({
        'step': 7, 'name': 'Key Agreement Verification',
        'description': 'Verify both parties derived the same shared secret',
        'data': {
            'agreement_status': 'Success' if agreement else 'Failed',
            'alice_secret_hash': hashlib.sha256(alice_shared).hexdigest()[:32] + '...',
            'bob_secret_hash': hashlib.sha256(bob_shared).hexdigest()[:32] + '...',
            'secrets_match': str(agreement)
        }
    })
    
    derived_key = hashlib.sha256(alice_shared).digest()
    steps.append({
        'step': 8, 'name': 'Symmetric Key Derivation',
        'description': 'Derive AES-256 key from shared secret using SHA-256',
        'data': {
            'derivation_function': 'SHA-256', 'derived_key_length': len(derived_key),
            'derived_key_bits': len(derived_key) * 8,
            'derived_key_preview': derived_key[:16].hex() + '...',
            'usage': 'Can be used for AES encryption'
        }
    })
    
    return {
        'steps': steps, 'shared_secret': alice_shared.hex(),
        'derived_key': derived_key.hex(), 'agreement': agreement
    }

def simulate_hash(input_bytes):
    """Simulate SHA-256 hashing step by step"""
    steps = []
    
    steps.append({
        'step': 1, 'name': 'Input Preparation',
        'description': 'Convert input data to bytes for hashing',
        'data': {
            'input_length': len(input_bytes),
            'input_preview': input_bytes[:32].hex() + ('...' if len(input_bytes) > 32 else ''),
            'input_type': 'Binary data'
        }
    })
    
    bit_length = len(input_bytes) * 8
    padding_needed = (448 - (bit_length % 512)) % 512
    padding_bytes = padding_needed // 8
    total_padded = len(input_bytes) + padding_bytes + 8
    
    steps.append({
        'step': 2, 'name': 'Message Padding',
        'description': 'Add padding to align message to 512-bit blocks',
        'data': {
            'original_bits': bit_length, 'padding_bits': padding_needed,
            'length_field': '64 bits', 'total_padded_bytes': total_padded,
            'total_blocks': total_padded // 64
        }
    })
    
    block_count = (total_padded + 63) // 64
    steps.append({
        'step': 3, 'name': 'Block Division',
        'description': 'Divide padded message into 512-bit (64-byte) blocks',
        'data': {
            'block_size': '512 bits (64 bytes)', 'total_blocks': block_count,
            'processing_order': 'Sequential'
        }
    })
    
    steps.append({
        'step': 4, 'name': 'Hash Initialization',
        'description': 'Initialize SHA-256 hash values (H0-H7)',
        'data': {
            'algorithm': 'SHA-256', 'initial_values': '8 x 32-bit constants',
            'h0': '6a09e667', 'h1': 'bb67ae85', 'rounds_per_block': '64'
        }
    })
    
    steps.append({
        'step': 5, 'name': 'Compression Function',
        'description': 'Process each block through 64 rounds of compression',
        'data': {
            'rounds': '64',
            'operations': 'Bitwise AND, XOR, rotations, additions',
            'constants': '64 round constants (K)',
            'working_variables': '8 (a, b, c, d, e, f, g, h)'
        }
    })
    
    hash_start = time.time()
    hash_obj = hashlib.sha256(input_bytes)
    hash_digest = hash_obj.hexdigest()
    hash_time = (time.time() - hash_start) * 1000
    
    steps.append({
        'step': 6, 'name': 'Hash Computation',
        'description': 'Compute final SHA-256 hash digest',
        'data': {
            'computation_time_ms': f"{hash_time:.4f}",
            'hash_length': '256 bits (32 bytes)', 'hash_hex': hash_digest,
            'hash_preview': hash_digest[:32] + '...'
        }
    })
    
    steps.append({
        'step': 7, 'name': 'Hash Properties',
        'description': 'SHA-256 cryptographic properties',
        'data': {
            'deterministic': 'Same input always produces same hash',
            'collision_resistance': 'Computationally infeasible to find collisions',
            'avalanche_effect': 'Small input change drastically changes output',
            'one_way': 'Cannot reverse hash to get original input',
            'fixed_output': '256 bits regardless of input size'
        }
    })
    
    steps.append({
        'step': 8, 'name': 'Hash Applications',
        'description': 'Common uses of SHA-256 hashing',
        'data': {
            'use_case_1': 'Data integrity verification',
            'use_case_2': 'Digital signatures',
            'use_case_3': 'Password hashing (with salt)',
            'use_case_4': 'Blockchain (Bitcoin)',
            'use_case_5': 'HMAC for message authentication'
        }
    })
    
    return {'steps': steps, 'hash': hash_digest, 'hash_time': float(hash_time)}

@app.route('/')
def index():
    with open('crypto_frontend.html', 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/api/aes-simulate', methods=['POST'])
def aes_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key, iv = secrets.token_bytes(32), secrets.token_bytes(12)
        simulation = simulate_aes_gcm(input_bytes, key, iv)
        return jsonify({'success': True, 'simulation': simulation})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/rsa-simulate', methods=['POST'])
def rsa_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        simulation = simulate_rsa(input_bytes)
        return jsonify({'success': True, 'simulation': simulation})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ecdh-simulate', methods=['POST'])
def ecdh_simulate():
    try:
        simulation = simulate_ecdh()
        return jsonify({'success': True, 'simulation': simulation})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/hash-simulate', methods=['POST'])
def hash_simulate():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        simulation = simulate_hash(input_bytes)
        return jsonify({'success': True, 'simulation': simulation})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/aes', methods=['POST'])
def aes_encrypt():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        key, iv = secrets.token_bytes(32), secrets.token_bytes(12)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        start_time = time.time()
        encrypted_data = encryptor.update(input_bytes) + encryptor.finalize()
        encrypt_time = (time.time() - start_time) * 1000
        tag = encryptor.tag
        
        return jsonify({
            'success': True, 'originalName': data['name'], 'originalSize': data['size'],
            'encryptedSize': len(encrypted_data), 'iv': iv.hex(), 'tag': tag.hex(),
            'encryptTime': f"{encrypt_time:.2f}",
            'encrypted': base64.b64encode(encrypted_data).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/rsa', methods=['POST'])
def rsa_encrypt():
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
            'success': True, 'originalName': data['name'], 'originalSize': data['size'],
            'encryptedSize': len(encrypted_data), 'keygenTime': f"{keygen_time:.0f}",
            'encrypted': base64.b64encode(encrypted_data).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ecdh', methods=['POST'])
def ecdh_exchange():
    try:
        alice_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        bob_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        alice_shared = alice_private.exchange(ec.ECDH(), bob_private.public_key())
        bob_shared = bob_private.exchange(ec.ECDH(), alice_private.public_key())
        
        return jsonify({
            'success': True, 'keyAgreement': alice_shared == bob_shared,
            'sharedKeyLength': len(alice_shared), 'sharedKey': alice_shared.hex()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/hash', methods=['POST'])
def hash_data():
    try:
        data = request.json
        input_bytes = base64.b64decode(data['data']) if data['type'] == 'file' else data['data'].encode('utf-8')
        
        start_time = time.time()
        hash_digest = hashlib.sha256(input_bytes).hexdigest()
        hash_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True, 'originalName': data['name'], 'originalSize': data['size'],
            'hash': hash_digest, 'hashTime': f"{hash_time:.2f}"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    print("🔐 Crypto Tool Server Starting...")
    print("Open: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)