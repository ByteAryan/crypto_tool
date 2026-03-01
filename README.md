# Crypto Tool - Interactive Cryptographic Algorithm Simulator

A comprehensive educational cryptographic tool built with Python that provides interactive visualizations and step-by-step simulations of popular encryption algorithms. Perfect for learning, teaching, and understanding how cryptographic algorithms work under the hood.

## 🎯 Features

### 🔐 Supported Cryptographic Algorithms

1. **AES-256-GCM (Advanced Encryption Standard)**
   - Symmetric encryption with Galois/Counter Mode
   - 256-bit key size for maximum security
   - Built-in authentication tag for data integrity
   - Step-by-step visualization of encryption process

2. **RSA-OAEP (RSA with OAEP Padding)**
   - Asymmetric encryption with 2048-bit keys
   - Optimal Asymmetric Encryption Padding (OAEP)
   - Public/private key pair generation
   - Detailed visualization of key generation and encryption

3. **ECDH (Elliptic Curve Diffie-Hellman)**
   - Key exchange using SECP256R1 (P-256) curve
   - Secure shared secret generation
   - Demonstrates key agreement between two parties
   - AES key derivation from shared secret

4. **SHA-256 (Secure Hash Algorithm)**
   - Cryptographic hashing with 256-bit output
   - Avalanche effect demonstration
   - Block-by-block processing visualization
   - Performance benchmarking

### 🎨 Three Interface Modes

#### 1. **Web Application** (Recommended)
- Beautiful gradient UI with interactive animations
- Real-time step-by-step algorithm visualization
- File upload and encryption support
- Binary download capabilities
- Decryption interface for encrypted files
- Supports both text and file inputs
- Animated educational visualizations:
  - Text-to-hex conversion
  - Block division
  - XOR operations
  - Elliptic curve visualization
  - Hash compression rounds
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
```bash
pip install cryptography flask
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
   - Choose between AES, RSA, ECDH, or SHA-256
   - Input text or upload files
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

### Simulation Endpoints
- `POST /api/aes-simulate` - Run AES-GCM simulation
- `POST /api/rsa-simulate` - Run RSA-OAEP simulation
- `POST /api/ecdh-simulate` - Run ECDH key exchange simulation
- `POST /api/hash-simulate` - Run SHA-256 hashing simulation

### Encryption/Decryption Endpoints
- `POST /api/aes` - Encrypt data with AES-GCM
- `POST /api/rsa` - Encrypt data with RSA-OAEP
- `POST /api/ecdh` - Perform ECDH key exchange
- `POST /api/hash` - Generate SHA-256 hash

### Download Endpoints
- `POST /api/download-aes-binary` - Download encrypted AES binary
- `POST /api/download-rsa-binary` - Download encrypted RSA binary
- `POST /api/download-ecdh-binary` - Download ECDH key material
- `POST /api/download-hash-binary` - Download hash output

### Decryption Endpoints
- `POST /api/decrypt-aes` - Decrypt AES-GCM encrypted data
- `POST /api/decrypt-rsa` - Decrypt RSA-OAEP encrypted data
- `POST /api/download-decrypted` - Download decrypted file

## 📁 Project Structure

```
crypto_tool/
├── main.py                    # Main entry point for CLI/GUI
├── crypto_web_app.py          # Flask web application
├── crypto_frontend.html       # Web UI with animations
├── config.py                  # Configuration settings
├── README.md                  # This file
├── algorithms/
│   ├── __init__.py
│   └── aes.py                 # AES-CBC implementation
├── simulation/
│   ├── __init__.py
│   ├── simulator.py           # Command-line simulator
│   └── gui_simulator.py       # Tkinter GUI simulator
├── utils/
│   ├── __init__.py
│   ├── key_generator.py       # Cryptographic key generation
│   └── file_handler.py        # File I/O utilities
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

- How AES block cipher mode works
- RSA key generation and OAEP padding
- Elliptic curve cryptography principles
- Hash function properties and avalanche effect
- Difference between symmetric and asymmetric encryption
- Authenticated encryption with GCM mode
- Key exchange protocols

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
- **Flask** - Web framework
- **cryptography** - Cryptographic primitives library
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
