import tkinter as tk
from utils import key_generator
from algorithms import aes
import config
import base64
import time

class AESGuiSimulator:
    def __init__(self, master):
        self.master = master
        master.title("AES Block-by-Block Simulation")

        # Input
        self.label = tk.Label(master, text="Enter Text to Encrypt:")
        self.label.pack(pady=5)

        self.text_entry = tk.Entry(master, width=50)
        self.text_entry.pack(pady=5)

        # Buttons
        self.start_button = tk.Button(master, text="Start Simulation", command=self.start_simulation)
        self.start_button.pack(pady=10)

        # Output Text Area
        self.output_text = tk.Text(master, height=25, width=80)
        self.output_text.pack(pady=5)

        # Define colors for tags
        self.output_text.tag_configure("step", foreground="blue", font=("Helvetica", 10, "bold"))
        self.output_text.tag_configure("plaintext", foreground="green")
        self.output_text.tag_configure("keyiv", foreground="purple")
        self.output_text.tag_configure("cipher", foreground="orange")
        self.output_text.tag_configure("decrypted", foreground="brown")
        self.output_text.tag_configure("final", foreground="red", font=("Helvetica", 11, "bold"))

    def write_colored(self, text, tag):
        self.output_text.insert(tk.END, text + "\n", tag)
        self.output_text.see(tk.END)  # Auto-scroll
        self.master.update()
        time.sleep(0.5)

    def start_simulation(self):
        self.output_text.delete("1.0", tk.END)
        plaintext = self.text_entry.get().encode()

        # Step 1: Generate Key and IV
        self.write_colored("Step 1: Generating Key and IV...", "step")
        key = key_generator.generate_aes_key(config.DEFAULT_KEY_SIZE)
        iv = key_generator.generate_iv(config.DEFAULT_BLOCK_SIZE)
        self.write_colored(f"Key (hex): {key.hex()}", "keyiv")
        self.write_colored(f"IV  (hex): {iv.hex()}\n", "keyiv")

        # Step 2: Show Plaintext
        self.write_colored("Step 2: Showing Plaintext...", "step")
        self.write_colored(f"Plaintext: {plaintext.decode()}\n", "plaintext")

        # Step 3: Encrypt
        self.write_colored("Step 3: Encrypting using AES-CBC...", "step")
        ciphertext = aes.encrypt(plaintext, key, iv)
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        self.write_colored(f"Encrypted (bytes): {ciphertext}", "cipher")
        self.write_colored(f"Ciphertext (Base64): {ciphertext_b64}\n", "cipher")

        # Step 4: Decrypt
        self.write_colored("Step 4: Decrypting the Ciphertext...", "step")
        decrypted = aes.decrypt(ciphertext, key, iv)
        self.write_colored(f"Decrypted (bytes): {decrypted}", "decrypted")
        self.write_colored(f"Recovered Text: {decrypted.decode()}\n", "decrypted")

        # Final Step
        self.write_colored("***Complete***","final")
