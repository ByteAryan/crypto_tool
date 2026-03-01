"""
Comprehensive test script for all encryption/decryption functionality.
Tests text and file encryption/decryption for cross-platform compatibility.
"""
import os
import sys
import tempfile

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from algorithms import aes
from utils import key_generator, file_handler, file_crypto


def test_text_encryption_cbc():
    """Test AES-CBC text encryption and decryption."""
    print("\n" + "="*60)
    print("TEST 1: AES-CBC Text Encryption/Decryption")
    print("="*60)
    
    try:
        # Test data
        plaintext = b"Hello, World! This is a test message for AES-CBC encryption."
        key = key_generator.generate_aes_key(32)
        iv = key_generator.generate_iv(16)
        
        print(f"Original text: {plaintext.decode()}")
        print(f"Text length: {len(plaintext)} bytes")
        
        # Encrypt
        ciphertext = aes.encrypt(plaintext, key, iv)
        print(f"✓ Encryption successful")
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        print(f"Ciphertext (first 32 bytes): {ciphertext[:32].hex()}...")
        
        # Decrypt
        decrypted = aes.decrypt(ciphertext, key, iv)
        print(f"✓ Decryption successful")
        print(f"Decrypted text: {decrypted.decode()}")
        
        # Verify
        if plaintext == decrypted:
            print("✅ TEST PASSED: Decryption matches original")
            return True
        else:
            print("❌ TEST FAILED: Decryption does not match original")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_text_encryption_gcm():
    """Test AES-GCM text encryption and decryption."""
    print("\n" + "="*60)
    print("TEST 2: AES-GCM Text Encryption/Decryption")
    print("="*60)
    
    try:
        # Test data
        plaintext = b"Hello, World! This is a test message for AES-GCM encryption with authentication."
        key = key_generator.generate_aes_key(32)
        iv = key_generator.generate_iv(12)  # GCM uses 96-bit IV
        
        print(f"Original text: {plaintext.decode()}")
        print(f"Text length: {len(plaintext)} bytes")
        
        # Encrypt
        ciphertext, tag = aes.encrypt_gcm(plaintext, key, iv)
        print(f"✓ Encryption successful")
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        print(f"Authentication tag: {tag.hex()}")
        
        # Decrypt
        decrypted = aes.decrypt_gcm(ciphertext, key, iv, tag)
        print(f"✓ Decryption successful")
        print(f"Decrypted text: {decrypted.decode()}")
        
        # Verify
        if plaintext == decrypted:
            print("✅ TEST PASSED: Decryption matches original")
            return True
        else:
            print("❌ TEST FAILED: Decryption does not match original")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_file_encryption_cbc():
    """Test AES-CBC file encryption and decryption."""
    print("\n" + "="*60)
    print("TEST 3: AES-CBC File Encryption/Decryption")
    print("="*60)
    
    temp_dir = tempfile.gettempdir()
    test_file = os.path.join(temp_dir, "test_input.txt")
    encrypted_file = os.path.join(temp_dir, "test_encrypted_cbc.enc")
    decrypted_file = os.path.join(temp_dir, "test_decrypted_cbc.txt")
    
    try:
        # Create test file
        test_data = b"This is a test file for AES-CBC encryption.\n" * 10
        file_handler.write_file_bytes(test_file, test_data)
        print(f"✓ Created test file: {test_file}")
        print(f"File size: {len(test_data)} bytes")
        
        # Encrypt file
        result = file_crypto.encrypt_file_cbc(test_file, encrypted_file)
        print(f"✓ File encrypted successfully")
        print(f"Mode: {result.mode}")
        print(f"Key: {result.key.hex()[:32]}...")
        print(f"IV: {result.iv.hex()}")
        
        # Decrypt file
        decrypted_data = file_crypto.decrypt_file_from_json(encrypted_file, decrypted_file)
        print(f"✓ File decrypted successfully")
        
        # Verify
        if test_data == decrypted_data:
            print("✅ TEST PASSED: Decrypted file matches original")
            
            # Cleanup
            cleanup_files = [test_file, encrypted_file, decrypted_file]
            for f in cleanup_files:
                if os.path.exists(f):
                    os.remove(f)
            print("✓ Cleaned up test files")
            return True
        else:
            print("❌ TEST FAILED: Decrypted file does not match original")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_file_encryption_gcm():
    """Test AES-GCM file encryption and decryption."""
    print("\n" + "="*60)
    print("TEST 4: AES-GCM File Encryption/Decryption")
    print("="*60)
    
    temp_dir = tempfile.gettempdir()
    test_file = os.path.join(temp_dir, "test_input_gcm.txt")
    encrypted_file = os.path.join(temp_dir, "test_encrypted_gcm.enc")
    decrypted_file = os.path.join(temp_dir, "test_decrypted_gcm.txt")
    
    try:
        # Create test file
        test_data = b"This is a test file for AES-GCM authenticated encryption.\n" * 10
        file_handler.write_file_bytes(test_file, test_data)
        print(f"✓ Created test file: {test_file}")
        print(f"File size: {len(test_data)} bytes")
        
        # Encrypt file
        result = file_crypto.encrypt_file_gcm(test_file, encrypted_file)
        print(f"✓ File encrypted successfully")
        print(f"Mode: {result.mode}")
        print(f"Key: {result.key.hex()[:32]}...")
        print(f"IV: {result.iv.hex()}")
        print(f"Tag: {result.tag.hex()}")
        
        # Decrypt file
        decrypted_data = file_crypto.decrypt_file_from_json(encrypted_file, decrypted_file)
        print(f"✓ File decrypted successfully")
        
        # Verify
        if test_data == decrypted_data:
            print("✅ TEST PASSED: Decrypted file matches original")
            
            # Cleanup
            cleanup_files = [test_file, encrypted_file, decrypted_file]
            for f in cleanup_files:
                if os.path.exists(f):
                    os.remove(f)
            print("✓ Cleaned up test files")
            return True
        else:
            print("❌ TEST FAILED: Decrypted file does not match original")
            return False
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_padding_validation():
    """Test that invalid padding is detected."""
    print("\n" + "="*60)
    print("TEST 5: Padding Validation")
    print("="*60)
    
    try:
        plaintext = b"Test message"
        key = key_generator.generate_aes_key(32)
        iv = key_generator.generate_iv(16)
        
        # Encrypt
        ciphertext = aes.encrypt(plaintext, key, iv)
        
        # Corrupt the ciphertext (last byte)
        corrupted = bytearray(ciphertext)
        corrupted[-1] ^= 0xFF
        corrupted = bytes(corrupted)
        
        # Try to decrypt corrupted data
        try:
            aes.decrypt(corrupted, key, iv)
            print("❌ TEST FAILED: Invalid padding was not detected")
            return False
        except ValueError as e:
            print(f"✓ Invalid padding correctly detected: {e}")
            print("✅ TEST PASSED: Padding validation works")
            return True
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_gcm_authentication():
    """Test that GCM authentication tag verification works."""
    print("\n" + "="*60)
    print("TEST 6: GCM Authentication Tag Verification")
    print("="*60)
    
    try:
        plaintext = b"Test message for authentication"
        key = key_generator.generate_aes_key(32)
        iv = key_generator.generate_iv(12)
        
        # Encrypt
        ciphertext, tag = aes.encrypt_gcm(plaintext, key, iv)
        
        # Corrupt the authentication tag
        corrupted_tag = bytearray(tag)
        corrupted_tag[0] ^= 0xFF
        corrupted_tag = bytes(corrupted_tag)
        
        # Try to decrypt with corrupted tag
        try:
            aes.decrypt_gcm(ciphertext, key, iv, corrupted_tag)
            print("❌ TEST FAILED: Invalid auth tag was not detected")
            return False
        except Exception as e:
            print(f"✓ Invalid auth tag correctly detected: {type(e).__name__}")
            print("✅ TEST PASSED: GCM authentication works")
            return True
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_empty_data():
    """Test encryption/decryption of empty data."""
    print("\n" + "="*60)
    print("TEST 7: Empty Data Handling")
    print("="*60)
    
    try:
        plaintext = b""
        key = key_generator.generate_aes_key(32)
        
        # Test CBC
        iv_cbc = key_generator.generate_iv(16)
        ciphertext_cbc = aes.encrypt(plaintext, key, iv_cbc)
        decrypted_cbc = aes.decrypt(ciphertext_cbc, key, iv_cbc)
        
        if plaintext == decrypted_cbc:
            print("✓ CBC mode handles empty data correctly")
        else:
            print("❌ CBC mode failed with empty data")
            return False
        
        # Test GCM
        iv_gcm = key_generator.generate_iv(12)
        ciphertext_gcm, tag = aes.encrypt_gcm(plaintext, key, iv_gcm)
        decrypted_gcm = aes.decrypt_gcm(ciphertext_gcm, key, iv_gcm, tag)
        
        if plaintext == decrypted_gcm:
            print("✓ GCM mode handles empty data correctly")
        else:
            print("❌ GCM mode failed with empty data")
            return False
        
        print("✅ TEST PASSED: Empty data handled correctly")
        return True
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def test_large_data():
    """Test encryption/decryption of large data."""
    print("\n" + "="*60)
    print("TEST 8: Large Data Encryption/Decryption")
    print("="*60)
    
    try:
        # Generate 1MB of test data
        plaintext = b"A" * (1024 * 1024)
        key = key_generator.generate_aes_key(32)
        
        print(f"Testing with {len(plaintext)} bytes (1 MB)")
        
        # Test CBC
        iv_cbc = key_generator.generate_iv(16)
        ciphertext_cbc = aes.encrypt(plaintext, key, iv_cbc)
        decrypted_cbc = aes.decrypt(ciphertext_cbc, key, iv_cbc)
        
        if plaintext == decrypted_cbc:
            print("✓ CBC mode handles 1MB data correctly")
        else:
            print("❌ CBC mode failed with 1MB data")
            return False
        
        # Test GCM
        iv_gcm = key_generator.generate_iv(12)
        ciphertext_gcm, tag = aes.encrypt_gcm(plaintext, key, iv_gcm)
        decrypted_gcm = aes.decrypt_gcm(ciphertext_gcm, key, iv_gcm, tag)
        
        if plaintext == decrypted_gcm:
            print("✓ GCM mode handles 1MB data correctly")
        else:
            print("❌ GCM mode failed with 1MB data")
            return False
        
        print("✅ TEST PASSED: Large data handled correctly")
        return True
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        return False


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("CRYPTO TOOL - COMPREHENSIVE TEST SUITE")
    print("="*60)
    print(f"Platform: {sys.platform}")
    print(f"Python Version: {sys.version}")
    
    tests = [
        ("Text Encryption (CBC)", test_text_encryption_cbc),
        ("Text Encryption (GCM)", test_text_encryption_gcm),
        ("File Encryption (CBC)", test_file_encryption_cbc),
        ("File Encryption (GCM)", test_file_encryption_gcm),
        ("Padding Validation", test_padding_validation),
        ("GCM Authentication", test_gcm_authentication),
        ("Empty Data", test_empty_data),
        ("Large Data (1MB)", test_large_data),
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
