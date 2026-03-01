"""
Test script for all new encryption algorithms.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from algorithms import symmetric, classical, ecc
import secrets


def test_des():
    """Test DES encryption/decryption."""
    print("\n" + "="*60)
    print("TEST: DES Encryption/Decryption")
    print("="*60)
    
    try:
        plaintext = b"Test DES encryption!"
        key = symmetric.generate_des_key()
        iv = secrets.token_bytes(8)
        
        print(f"Plaintext: {plaintext.decode()}")
        
        ciphertext = symmetric.encrypt_des(plaintext, key, iv)
        print(f"✓ Encryption successful ({len(ciphertext)} bytes)")
        
        decrypted = symmetric.decrypt_des(ciphertext, key, iv)
        print(f"✓ Decryption successful")
        
        if plaintext == decrypted:
            print("✅ TEST PASSED: DES works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_3des():
    """Test 3DES encryption/decryption."""
    print("\n" + "="*60)
    print("TEST: 3DES Encryption/Decryption")
    print("="*60)
    
    try:
        plaintext = b"Test 3DES encryption!"
        key = symmetric.generate_3des_key()
        iv = secrets.token_bytes(8)
        
        print(f"Plaintext: {plaintext.decode()}")
        
        ciphertext = symmetric.encrypt_3des(plaintext, key, iv)
        print(f"✓ Encryption successful ({len(ciphertext)} bytes)")
        
        decrypted = symmetric.decrypt_3des(ciphertext, key, iv)
        print(f"✓ Decryption successful")
        
        if plaintext == decrypted:
            print("✅ TEST PASSED: 3DES works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_blowfish():
    """Test Blowfish encryption/decryption."""
    print("\n" + "="*60)
    print("TEST: Blowfish Encryption/Decryption")
    print("="*60)
    
    try:
        plaintext = b"Test Blowfish encryption!"
        key = symmetric.generate_blowfish_key(16)
        iv = secrets.token_bytes(8)
        
        print(f"Plaintext: {plaintext.decode()}")
        
        ciphertext = symmetric.encrypt_blowfish(plaintext, key, iv)
        print(f"✓ Encryption successful ({len(ciphertext)} bytes)")
        
        decrypted = symmetric.decrypt_blowfish(ciphertext, key, iv)
        print(f"✓ Decryption successful")
        
        if plaintext == decrypted:
            print("✅ TEST PASSED: Blowfish works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_chacha20():
    """Test ChaCha20 encryption/decryption."""
    print("\n" + "="*60)
    print("TEST: ChaCha20 Encryption/Decryption")
    print("="*60)
    
    try:
        plaintext = b"Test ChaCha20 stream cipher encryption!"
        key = symmetric.generate_chacha20_key()
        nonce = symmetric.generate_chacha20_nonce()
        
        print(f"Plaintext: {plaintext.decode()}")
        
        ciphertext = symmetric.encrypt_chacha20(plaintext, key, nonce)
        print(f"✓ Encryption successful ({len(ciphertext)} bytes)")
        
        decrypted = symmetric.decrypt_chacha20(ciphertext, key, nonce)
        print(f"✓ Decryption successful")
        
        if plaintext == decrypted:
            print("✅ TEST PASSED: ChaCha20 works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_playfair():
    """Test Playfair cipher."""
    print("\n" + "="*60)
    print("TEST: Playfair Cipher")
    print("="*60)
    
    try:
        plaintext = "HELLO WORLD"
        key = "KEYWORD"
        
        cipher = classical.PlayfairCipher(key)
        print(f"Plaintext: {plaintext}")
        print(f"Key: {key}")
        
        ciphertext = cipher.encrypt(plaintext)
        print(f"✓ Encryption successful: {ciphertext}")
        
        decrypted = cipher.decrypt(ciphertext)
        print(f"✓ Decryption successful: {decrypted}")
        
        # Note: Playfair may add X padding, so we check if decrypted starts with plaintext
        if decrypted.replace('X', '').startswith(plaintext.replace(' ', '')):
            print("✅ TEST PASSED: Playfair works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_hill():
    """Test Hill cipher."""
    print("\n" + "="*60)
    print("TEST: Hill Cipher")
    print("="*60)
    
    try:
        plaintext = "HELLO"
        key_matrix = [[3, 3], [2, 5]]
        
        cipher = classical.HillCipher(key_matrix)
        print(f"Plaintext: {plaintext}")
        print(f"Key Matrix: {key_matrix}")
        
        ciphertext = cipher.encrypt(plaintext)
        print(f"✓ Encryption successful: {ciphertext}")
        
        decrypted = cipher.decrypt(ciphertext)
        print(f"✓ Decryption successful: {decrypted}")
        
        # Hill cipher may add padding, so we check if it starts with plaintext
        if decrypted.startswith(plaintext):
            print("✅ TEST PASSED: Hill cipher works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_vigenere():
    """Test Vigenère cipher."""
    print("\n" + "="*60)
    print("TEST: Vigenère Cipher")
    print("="*60)
    
    try:
        plaintext = "HELLO WORLD FROM VIGENERE CIPHER"
        key = "SECRET"
        
        cipher = classical.VigenereCipher(key)
        print(f"Plaintext: {plaintext}")
        print(f"Key: {key}")
        
        ciphertext = cipher.encrypt(plaintext)
        print(f"✓ Encryption successful: {ciphertext}")
        
        decrypted = cipher.decrypt(ciphertext)
        print(f"✓ Decryption successful: {decrypted}")
        
        if plaintext == decrypted:
            print("✅ TEST PASSED: Vigenère works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_railfence():
    """Test Double Rail Fence cipher."""
    print("\n" + "="*60)
    print("TEST: Double Rail Fence Cipher")
    print("="*60)
    
    try:
        plaintext = "HELLO WORLD FROM RAIL FENCE"
        rails1 = 3
        rails2 = 4
        
        cipher = classical.DoubleRailFenceCipher(rails1, rails2)
        print(f"Plaintext: {plaintext}")
        print(f"Rails: {rails1}, {rails2}")
        
        ciphertext = cipher.encrypt(plaintext)
        print(f"✓ Encryption successful: {ciphertext}")
        
        decrypted = cipher.decrypt(ciphertext)
        print(f"✓ Decryption successful: {decrypted}")
        
        if plaintext.replace(' ', '') == decrypted:
            print("✅ TEST PASSED: Rail Fence works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            print(f"Expected: {plaintext.replace(' ', '')}")
            print(f"Got: {decrypted}")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_columnar():
    """Test Double Columnar Transposition cipher."""
    print("\n" + "="*60)
    print("TEST: Double Columnar Transposition")
    print("="*60)
    
    try:
        plaintext = "HELLO WORLD"
        key1 = "HACK"
        key2 = "CODE"
        
        cipher = classical.DoubleColumnarTransposition(key1, key2)
        print(f"Plaintext: {plaintext}")
        print(f"Keys: {key1}, {key2}")
        
        ciphertext = cipher.encrypt(plaintext)
        print(f"✓ Encryption successful: {ciphertext}")
        
        decrypted = cipher.decrypt(ciphertext)
        print(f"✓ Decryption successful: {decrypted}")
        
        # Remove padding X's from the end
        decrypted_clean = decrypted.rstrip('X')
        plaintext_clean = plaintext.replace(' ', '')
        
        if plaintext_clean == decrypted_clean:
            print("✅ TEST PASSED: Columnar Transposition works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            print(f"Expected: {plaintext_clean}")
            print(f"Got: {decrypted_clean}")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ecc():
    """Test ECC (ECIES) encryption/decryption."""
    print("\n" + "="*60)
    print("TEST: ECC (ECIES) Encryption/Decryption")
    print("="*60)
    
    try:
        plaintext = b"Test ECC encryption with ECIES!"
        
        private_key, public_key = ecc.generate_ecc_keypair()
        print(f"Plaintext: {plaintext.decode()}")
        print("✓ Key pair generated")
        
        encrypted_data = ecc.encrypt_ecc(plaintext, public_key)
        print(f"✓ Encryption successful")
        print(f"Ciphertext length: {len(encrypted_data['ciphertext'])} bytes")
        
        decrypted = ecc.decrypt_ecc(encrypted_data, private_key)
        print(f"✓ Decryption successful")
        
        if plaintext == decrypted:
            print("✅ TEST PASSED: ECC works correctly")
            return True
        else:
            print("❌ TEST FAILED: Decryption mismatch")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("NEW ALGORITHMS TEST SUITE")
    print("="*60)
    print(f"Platform: {sys.platform}")
    print(f"Python Version: {sys.version}")
    
    tests = [
        ("DES", test_des),
        ("3DES", test_3des),
        ("Blowfish", test_blowfish),
        ("ChaCha20", test_chacha20),
        ("Playfair Cipher", test_playfair),
        ("Hill Cipher", test_hill),
        ("Vigenère Cipher", test_vigenere),
        ("Double Rail Fence", test_railfence),
        ("Double Columnar Transposition", test_columnar),
        ("ECC (ECIES)", test_ecc),
    ]
    
    results = []
    for name, test_func in tests:
        result = test_func()
        results.append((name, result))
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status}: {name}")
    
    print("\n" + "="*60)
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! 🎉")
        print("="*60)
        return 0
    else:
        print(f"⚠️  {total - passed} test(s) failed")
        print("="*60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
