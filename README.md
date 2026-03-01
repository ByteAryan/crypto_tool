# Crypto Tool - Interactive Cryptographic Algorithm Simulator

A comprehensive educational cryptographic tool built with Python that provides interactive visualizations and step-by-step simulations of popular encryption algorithms. **Version 2.0 now includes 10 new algorithms!**

**✨ Version 2.0 Update:** Added DES, 3DES, Blowfish, ChaCha20, Playfair, Hill, Vigenère, Rail Fence, Columnar Transposition, and ECC! All with complete text/file encryption and simulation steps. See [CHANGELOG_v2.md](CHANGELOG_v2.md) for details.

## 🚀 Quick Start

```bash
# Clone the repository
cd crypto_tool

# Install dependencies
pip install cryptography flask numpy
# OR use requirements
pip install -r requirements.txt

# Run tests to verify everything works
python test_crypto.py
python test_new_algorithms.py

# Start the web application
python crypto_web_app.py
# Then open http://localhost:5000 in your browser

# OR run the command-line interface
python main.py
```

## 🎯 Features

### 🔐 Supported Cryptographic Algorithms

#### Modern Symmetric Ciphers
1. **AES-256-GCM (Advanced Encryption Standard)**
   - Symmetric encryption with Galois/Counter Mode
   - 256-bit key size for maximum security
   - Built-in authentication tag for data integrity
   - Step-by-step visualization of encryption process

2. **DES (Data Encryption Standard)** 🆕
   - Classic 56-bit symmetric cipher
   - Educational implementation with step-by-step simulation
   - Shows Feistel network structure

3. **3DES (Triple DES)** 🆕
   - Enhanced DES with triple encryption
   - 168-bit effective key strength
   - Demonstrates EDE (Encrypt-Decrypt-Encrypt) mode

4. **Blowfish** 🆕
   - Fast symmetric block cipher
   - Variable key length (4-56 bytes)
   - Shows P-array and S-box generation

5. **ChaCha20** 🆕
   - Modern stream cipher
   - 256-bit key, very fast
   - No padding required

#### Asymmetric Ciphers
6. **RSA-OAEP (RSA with OAEP Padding)**
   - Asymmetric encryption with 2048-bit keys
   - Optimal Asymmetric Encryption Padding (OAEP)
   - Public/private key pair generation
   - Detailed visualization of key generation and encryption

7. **ECC (Elliptic Curve Cryptography)** 🆕
   - Uses ECIES (Elliptic Curve Integrated Encryption Scheme)
   - 256-bit elliptic curve (secp256r1)
   - Perfect forward secrecy
   - Combines ECDH + KDF + AES-GCM

#### Classical Ciphers (Educational)
8. **Playfair Cipher** 🆕
   - 5×5 matrix-based substitution
   - Digraph encryption
   - Historical cipher with educational value

9. **Hill Cipher** 🆕
   - Matrix-based encryption using linear algebra
   - 2×2 matrix multiplication (mod 26)
   - Demonstrates mathematical cryptography

10. **Vigenère Cipher** 🆕
    - Polyalphabetic substitution cipher
    - Variable-length keyword
    - Classic cryptography algorithm

11. **Double Rail Fence Cipher** 🆕
    - Transposition cipher with zigzag pattern
    - Two-pass encryption
    - Classic steganographic technique

12. **Double Columnar Transposition** 🆕
    - Two-pass columnar transposition
    - Uses two keywords
    - World War era cipher

### 🎨 Three Interface Modes

#### 1. **Web Application** (Recommended)
- Beautiful gradient UI with interactive animations
- Real-time step-by-step algorithm visualization
- File upload and encryption support
- Binary download capabilities
- Decryption interface for encrypted files
- Supports both text and file inputs
- 12 different encryption algorithms available
- Animated educational visualizations:
  - Text-to-hex conversion
  - Block division and XOR operations
  - Feistel network structure (DES/3DES)
  - S-box and P-array generation (Blowfish)
  - Matrix operations (Hill cipher)
  - Transposition patterns (Rail Fence, Columnar)
  - Elliptic curve cryptography (ECC)
  - And much more!

#### 2. **GUI Simulator** (Tkinter)
- Desktop application with colorful output
- Interactive AES encryption/decryption
- Real-time step visualization
- Copy-paste friendly interface

#### 3. **Command-Line Interface**
- Quick encryption/decryption operations
- Base64 encoded output
- Detailed step-by-step console output
- Perfect for scripting and automation

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/ByteAryan/crypto_tool.git
cd crypto_tool
```

2. **Create a virtual environment (recommended):**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies:**
```bashpip install -r requirements.txt
```

Or install individually:
```bashpip install cryptography flask
```

## 📖 Usage

### Web Application (Recommended)

1. **Start the Flask server:**
```bash
python crypto_web_app.py
```

2. **Open your browser:**
Navigate to `http://localhost:5000`

3. **Features available:**
   - Choose from 12 algorithms: AES, RSA, DES, 3DES, Blowfish, ChaCha20, ECC, Playfair, Hill, Vigenère, Rail Fence, Columnar
   - Input text or upload files for encryption
   - Click "Encrypt & Run Simulation" to see step-by-step process
   - Click on individual steps to see animated visualizations
   - Download encrypted files or text results
   - Use the decryption interface to decrypt files

### GUI Simulator

1. **Launch the GUI:**
```bash
python main.py
```

2. **Select option 2** for GUI Simulation

3. **Features:**
   - Enter text in the input field
   - Click "Start Simulation"
   - Watch color-coded step-by-step encryption
   - See decryption process in real-time

### Command-Line Interface

1. **Launch CLI:**
```bash
python main.py
```

2. **Select option 1** for Command-line Simulation

3. **Follow the prompts** to enter text and see encryption/decryption

## 🔌 API Endpoints

The web application exposes RESTful API endpoints for programmatic access:

### Modern Symmetric Cipher Endpoints
- `POST /api/aes` & `/api/aes-simulate` - AES-256-GCM encryption & simulation
- `POST /api/des` & `/api/des-simulate` 🆕 - DES encryption & simulation
- `POST /api/3des` & `/api/3des-simulate` 🆕 - Triple DES encryption & simulation
- `POST /api/blowfish` & `/api/blowfish-simulate` 🆕 - Blowfish encryption & simulation
- `POST /api/chacha20` & `/api/chacha20-simulate` 🆕 - ChaCha20 encryption & simulation

### Asymmetric Cipher Endpoints
- `POST /api/rsa` & `/api/rsa-simulate` - RSA-OAEP encryption & simulation
- `POST /api/ecc` & `/api/ecc-simulate` 🆕 - ECC/ECIES encryption & simulation

### Classical Cipher Endpoints 🆕
- `POST /api/playfair` & `/api/playfair-simulate` - Playfair cipher encryption & simulation
- `POST /api/hill` & `/api/hill-simulate` - Hill cipher encryption & simulation
- `POST /api/vigenere` & `/api/vigenere-simulate` - Vigenère cipher encryption & simulation
- `POST /api/railfence` & `/api/railfence-simulate` - Double Rail Fence encryption & simulation
- `POST /api/columnar` & `/api/columnar-simulate` - Double Columnar Transposition encryption & simulation

### Utility Endpoints
- `POST /api/decrypt` - Universal decryption endpoint (supports all algorithms)

## 📁 Project Structure

```
crypto_tool/
├── main.py                    # Main entry point for CLI/GUI
├── crypto_web_app.py          # Flask web application (v2.0)
├── crypto_frontend.html       # Web UI with animations
├── config.py                  # Configuration settings
├── setup.py                   # Package installation
├── README.md                  # This file
├── CHANGELOG_v2.md            # Version 2.0 changelog 🆕
├── test_crypto.py             # Original algorithm tests
├── test_new_algorithms.py     # New algorithm tests 🆕
├── algorithms/
│   ├── __init__.py
│   ├── aes.py                 # AES-CBC/GCM implementation
│   ├── symmetric.py           # DES, 3DES, Blowfish, ChaCha20 🆕
│   ├── classical.py           # Classical ciphers 🆕
│   └── ecc.py                 # ECC/ECIES implementation 🆕
├── simulation/
│   ├── __init__.py
│   ├── simulator.py           # Command-line simulator
│   └── gui_simulator.py       # Tkinter GUI simulator
├── utils/
│   ├── __init__.py
│   ├── key_generator.py       # Cryptographic key generation
│   ├── file_handler.py        # File I/O utilities
│   └── file_crypto.py         # File encryption utilities 🆕
└── identification/
    └── __init__.py            # Future: Algorithm identification
```

## 🎓 Educational Value

This tool is designed for:
- **Students** learning cryptography concepts
- **Educators** teaching encryption algorithms
- **Developers** understanding crypto implementations
- **Security enthusiasts** exploring algorithm internals

### What You'll Learn

**Modern Cryptography:**
- How AES block cipher modes work (CBC, GCM)
- RSA key generation and OAEP padding
- DES and 3DES Feistel network structure
- Blowfish S-box and P-array generation
- ChaCha20 stream cipher operations
- Elliptic curve cryptography (ECC/ECIES)
- Authenticated encryption with GCM mode
- Difference between symmetric and asymmetric encryption

**Classical Cryptography:**
- Playfair cipher digraph substitution
- Hill cipher matrix operations
- Vigenère polyalphabetic substitution
- Rail Fence transposition patterns
- Columnar transposition techniques

**Security Concepts:**
- Padding schemes (PKCS7, OAEP)
- Key derivation functions (KDF)
- Authentication tags and integrity
- Perfect forward secrecy (ECC)

## 🔒 Security Notes

⚠️ **Important:** This tool is designed for **educational purposes only**. 

- Do not use for production-level encryption
- The web application runs in debug mode by default
- Keys are generated randomly and not stored securely
- This is a learning tool, not a security product

For production use, always:
- Use established cryptographic libraries
- Follow current security best practices
- Implement proper key management
- Use hardware security modules where appropriate

## 🛠️ Technologies Used

- **Python 3.8+** - Core programming language
- **Flask** - Web framework for REST API
- **cryptography** - Industry-standard cryptographic primitives
- **NumPy** - Mathematical operations for Hill cipher 🆕
- **Tkinter** - GUI framework (built-in)
- **HTML/CSS/JavaScript** - Frontend with Canvas animations

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Add more algorithms
- Improve visualizations
- Enhance documentation

## 📝 License

This project is open-source and available for educational use.

## 👤 Author

**ByteAryan**

## 🙏 Acknowledgments

- Built using the `cryptography` library by the Python Cryptographic Authority
- Inspired by the need for better cryptography education tools
- Animations designed to make complex concepts accessible

---

**Made with ❤️ for the cryptography community**
