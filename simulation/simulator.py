from utils import key_generator
import config
from algorithms import aes

def run_simulation(plaintext, key, iv):
    print("=== AES Encryption/Decryption Simulation ===\n")

    # Step 1: Show original text
    print("Step 1: Original Text")
    print(f"  {plaintext.decode()}")
    print("  ↓\n")

    # Step 2: Encrypt
    ciphertext = aes.encrypt(plaintext, key, iv)
    ciphertext_b64 = key_generator.to_base64(ciphertext)
    print("Step 2: Encrypted (AES)")
    print(f"  {ciphertext}")
    print("  ↓\n")

    # Step 3: Ciphertext for storage/transmission
    print("Step 3: Ciphertext (Base64, ready to transmit/store)")
    print(f"  {ciphertext_b64}")
    print("  ↓\n")

    # Step 4: Decrypt
    decrypted = aes.decrypt(ciphertext, key, iv)
    print("Step 4: Decrypted (AES)")
    print(f"  {decrypted}")
    print("  ↓\n")

    # Step 5: Recovered text
    print("Step 5: Recovered Original Text")
    print(f"  {decrypted.decode()}")
    print("\n✅ Encryption and Decryption Complete!\n")
