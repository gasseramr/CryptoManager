#!/usr/bin/env python3
"""
Basic Usage Examples for CryptoManager

This script demonstrates how to use the CryptoManager class for various
encryption and decryption tasks.
"""

import sys
import os

# Add the parent directory to the path to import CryptoManager
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from CryptoManager import CryptoManager

def main():
    """Demonstrate basic usage of CryptoManager."""
    print("🔐 CryptoManager - Basic Usage Examples\n")
    
    # Initialize the CryptoManager
    cm = CryptoManager()
    
    # Example 1: Caesar Cipher
    print("=== Example 1: Caesar Cipher ===")
    text = "Hello, World!"
    shift = 3
    encrypted = cm.caesar_encrypt(text, shift)
    decrypted = cm.caesar_decrypt(encrypted, shift)
    
    print(f"Original: {text}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print()
    
    # Example 2: XOR Cipher
    print("=== Example 2: XOR Cipher ===")
    text = "Secret message"
    key = "my_secret_key"
    encrypted = cm.xor_encrypt(text, key)
    decrypted = cm.xor_decrypt(encrypted, key)
    
    print(f"Original: {text}")
    print(f"Key: {key}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print()
    
    # Example 3: Vigenère Cipher
    print("=== Example 3: Vigenère Cipher ===")
    text = "CRYPTOGRAPHY"
    key = "KEY"
    encrypted = cm.vigenere_encrypt(text, key)
    decrypted = cm.vigenere_decrypt(encrypted, key)
    
    print(f"Original: {text}")
    print(f"Key: {key}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print()
    
    # Example 4: AES-256 Encryption
    print("=== Example 4: AES-256 Encryption ===")
    text = "This is a secret message that needs to be encrypted."
    password = "my_secure_password"
    
    # Encrypt
    result = cm.aes_encrypt(text, password)
    print(f"Original: {text}")
    print(f"Password: {password}")
    print(f"Ciphertext: {result['ciphertext']}")
    print(f"Salt: {result['salt']}")
    print(f"IV: {result['iv']}")
    
    # Decrypt
    decrypted = cm.aes_decrypt(
        result['ciphertext'],
        password,
        result['salt'],
        result['iv']
    )
    print(f"Decrypted: {decrypted}")
    print()
    
    # Example 5: RSA Encryption
    print("=== Example 5: RSA Encryption ===")
    # Generate RSA keys
    private_key, public_key = cm.generate_rsa_keys()
    
    text = "RSA encrypted message"
    encrypted = cm.rsa_encrypt(text, public_key)
    decrypted = cm.rsa_decrypt(encrypted, private_key)
    
    print(f"Original: {text}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print()
    
    # Example 6: Fernet Encryption
    print("=== Example 6: Fernet Encryption ===")
    text = "Fernet authenticated encryption"
    result = cm.fernet_encrypt(text)
    
    print(f"Original: {text}")
    print(f"Ciphertext: {result['ciphertext']}")
    print(f"Key: {result['key']}")
    
    decrypted = cm.fernet_decrypt(result['ciphertext'], result['key'])
    print(f"Decrypted: {decrypted}")
    print()
    
    # Example 7: Rail Fence Cipher
    print("=== Example 7: Rail Fence Cipher ===")
    text = "RAILFENCE"
    rails = 3
    encrypted = cm.railfence_encrypt(text, rails)
    decrypted = cm.railfence_decrypt(encrypted, rails)
    
    print(f"Original: {text}")
    print(f"Rails: {rails}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print()
    
    print("✅ All examples completed successfully!")

if __name__ == "__main__":
    main() 