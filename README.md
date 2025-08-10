# CryptoManager 🔐

A comprehensive Python cryptography toolkit that provides multiple encryption and decryption algorithms for educational and practical use.

## 🌟 Features

### Supported Encryption Algorithms

1. **Caesar Cipher** - Classic substitution cipher with configurable shift
2. **XOR Cipher** - Simple bitwise XOR encryption
3. **Vigenère Cipher** - Polyalphabetic substitution cipher
4. **AES-256** - Advanced Encryption Standard with CBC mode
5. **RSA** - Asymmetric encryption with 2048-bit keys
6. **Fernet** - Symmetric authenticated encryption
7. **Triple DES** - Triple Data Encryption Standard
8. **Blowfish** - Fast block cipher
9. **RC4** - Stream cipher (for educational purposes)
10. **Rail Fence** - Transposition cipher

### Key Features

- 🔒 **Multiple Algorithms**: Support for 10 different encryption methods
- 🛡️ **Security Focused**: Uses industry-standard cryptographic libraries
- 📝 **Educational**: Includes both classical and modern encryption methods
- 🔧 **Easy to Use**: Simple command-line interface
- 📦 **Self-Contained**: Minimal dependencies
- 🔑 **Key Management**: Automatic RSA key generation and management

## 📋 Requirements

- Python 3.7+
- cryptography library

## 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/CryptoManager.git
   cd CryptoManager
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python CryptoManager.py
   ```

## 📖 Usage

### Command Line Interface

The application provides an interactive menu system:

```bash
=== Cryptography Manager ===
1. Encrypt Text
2. Decrypt Text
3. Generate RSA Keys
4. Exit
```

### Example Usage

#### 1. Caesar Cipher
```python
from CryptoManager import CryptoManager

cm = CryptoManager()
encrypted = cm.caesar_encrypt("Hello World", 3)
decrypted = cm.caesar_decrypt(encrypted, 3)
print(f"Encrypted: {encrypted}")  # Khoor Zruog
print(f"Decrypted: {decrypted}")  # Hello World
```

#### 2. AES-256 Encryption
```python
# Encrypt
result = cm.aes_encrypt("Secret message", "my_password")
print(f"Ciphertext: {result['ciphertext']}")
print(f"Salt: {result['salt']}")
print(f"IV: {result['iv']}")

# Decrypt
decrypted = cm.aes_decrypt(
    result['ciphertext'], 
    "my_password", 
    result['salt'], 
    result['iv']
)
print(f"Decrypted: {decrypted}")
```

#### 3. RSA Encryption
```python
# Generate keys
private_key, public_key = cm.generate_rsa_keys()

# Encrypt with public key
encrypted = cm.rsa_encrypt("Secret message", public_key)

# Decrypt with private key
decrypted = cm.rsa_decrypt(encrypted, private_key)
```

## 🔐 Security Considerations

### Algorithm Security Levels

| Algorithm | Security Level | Use Case |
|-----------|---------------|----------|
| AES-256 | 🔒🔒🔒🔒🔒 | Production, high security |
| RSA-2048 | 🔒🔒🔒🔒🔒 | Asymmetric encryption |
| Fernet | 🔒🔒🔒🔒🔒 | Authenticated encryption |
| Triple DES | 🔒🔒🔒 | Legacy compatibility |
| Blowfish | 🔒🔒🔒 | Fast encryption |
| Vigenère | 🔒🔒 | Educational |
| Caesar | 🔒 | Educational only |
| XOR | 🔒 | Educational only |
| RC4 | ⚠️ | Educational only |
| Rail Fence | 🔒 | Educational only |

### Important Notes

- **Educational Algorithms**: Caesar, XOR, Vigenère, RC4, and Rail Fence are included for educational purposes only
- **Production Use**: For production applications, use AES-256, RSA, or Fernet
- **Key Management**: Always secure your encryption keys and passwords
- **Salt and IV**: Modern algorithms use random salt and initialization vectors for security

## 🏗️ Project Structure

```
CryptoManager/
├── CryptoManager.py      # Main application file
├── requirements.txt      # Python dependencies
├── README.md           # This file
├── examples/           # Usage examples
├── tests/             # Unit tests
└── docs/              # Documentation
```

## 🧪 Testing

Run the test suite:

```bash
python -m pytest tests/
```

## 📚 API Reference

### Core Methods

#### Classical Ciphers
- `caesar_encrypt(plaintext, shift)` - Caesar cipher encryption
- `caesar_decrypt(ciphertext, shift)` - Caesar cipher decryption
- `vigenere_encrypt(plaintext, key)` - Vigenère cipher encryption
- `vigenere_decrypt(ciphertext, key)` - Vigenère cipher decryption
- `railfence_encrypt(plaintext, rails)` - Rail fence encryption
- `railfence_decrypt(ciphertext, rails)` - Rail fence decryption

#### Modern Ciphers
- `aes_encrypt(plaintext, password)` - AES-256 encryption
- `aes_decrypt(ciphertext, password, salt, iv)` - AES-256 decryption
- `rsa_encrypt(plaintext, public_key)` - RSA encryption
- `rsa_decrypt(ciphertext, private_key)` - RSA decryption
- `fernet_encrypt(plaintext)` - Fernet encryption
- `fernet_decrypt(ciphertext, key)` - Fernet decryption

#### Legacy Ciphers
- `triple_des_encrypt(plaintext, password)` - Triple DES encryption
- `triple_des_decrypt(ciphertext, password, salt, iv)` - Triple DES decryption
- `blowfish_encrypt(plaintext, password)` - Blowfish encryption
- `blowfish_decrypt(ciphertext, password, salt, iv)` - Blowfish decryption

#### Stream Ciphers
- `xor_encrypt(plaintext, key)` - XOR encryption
- `xor_decrypt(ciphertext, key)` - XOR decryption
- `rc4_encrypt(plaintext, key)` - RC4 encryption
- `rc4_decrypt(ciphertext, key)` - RC4 decryption

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This project is for educational and research purposes. Some algorithms included are not suitable for production use. Always use industry-standard encryption for sensitive data.

## 🆘 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/yourusername/CryptoManager/issues) page
2. Create a new issue with detailed information
3. Include your Python version and operating system

## 📈 Roadmap

- [ ] Add more encryption algorithms (ChaCha20, Salsa20)
- [ ] Implement file encryption/decryption
- [ ] Add GUI interface
- [ ] Add password strength checker
- [ ] Implement secure key storage
- [ ] Add benchmarking tools
- [ ] Create Docker container
- [ ] Add API endpoints

---

**Made with ❤️ for cryptography enthusiasts** 