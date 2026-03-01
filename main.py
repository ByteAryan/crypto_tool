from algorithms import aes
from utils import key_generator
import config
from simulation.simulator import run_simulation
from simulation.gui_simulator import AESGuiSimulator
import tkinter as tk
import sys

def main():
    try:
        choice = input("Choose mode:\n1. Command-line Simulation\n2. GUI Simulation\nEnter 1 or 2: ")

        if choice == "2":
            # Run GUI simulation
            root = tk.Tk()
            gui = AESGuiSimulator(root)
            root.mainloop()
            return

        # Command-line simulation
        text_input = input("Enter text to encrypt: ")
        if not text_input:
            print("Error: Empty input provided")
            return
        
        plaintext = text_input.encode('utf-8')

        key = key_generator.generate_aes_key(config.DEFAULT_KEY_SIZE)
        iv = key_generator.generate_iv(config.DEFAULT_BLOCK_SIZE)

        print("\n=== AES Encryption/Decryption ===")
        print("Plaintext (bytes):", plaintext)

        ciphertext = aes.encrypt(plaintext, key, iv)
        print("Ciphertext (hex):", ciphertext.hex())

        decrypted = aes.decrypt(ciphertext, key, iv)
        print("Decrypted:", decrypted)
        
        # Verify decryption matches original
        if decrypted == plaintext:
            print("✅ Decryption successful - matches original plaintext")
        else:
            print("❌ Decryption failed - does not match original")

        print("\n=== Command-line Block Simulation ===")
        run_simulation(plaintext, key, iv)
    
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
