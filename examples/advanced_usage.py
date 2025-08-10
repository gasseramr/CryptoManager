#!/usr/bin/env python3
"""
Advanced Usage Examples for CryptoManager

This script demonstrates advanced usage patterns, security best practices,
and complex scenarios for the CryptoManager class.
"""

import sys
import os
import json
import time
import hashlib
from typing import Dict, Any

# Add the parent directory to the path to import CryptoManager
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from CryptoManager import CryptoManager

class SecureMessageHandler:
    """Advanced message handler with multiple encryption layers."""
    
    def __init__(self):
        self.cm = CryptoManager()
        self.session_keys = {}
    
    def create_secure_message(self, message: str, recipient_public_key, 
                            session_password: str) -> Dict[str, Any]:
        """
        Create a secure message with multiple layers of encryption.
        
        Args:
            message: The plaintext message
            recipient_public_key: RSA public key for the recipient
            session_password: Password for session encryption
            
        Returns:
            Dictionary containing encrypted message and metadata
        """
        # Layer 1: Encrypt with AES using session password
        aes_result = self.cm.aes_encrypt(message, session_password)
        
        # Layer 2: Encrypt the AES key with RSA
        aes_key_encrypted = self.cm.rsa_encrypt(session_password, recipient_public_key)
        
        # Create message structure
        secure_message = {
            'version': '1.0',
            'timestamp': time.time(),
            'aes_encrypted_data': aes_result,
            'encrypted_session_key': aes_key_encrypted,
            'algorithm': 'AES-256 + RSA-2048',
            'checksum': self._calculate_checksum(message)
        }
        
        return secure_message
    
    def decrypt_secure_message(self, secure_message: Dict[str, Any], 
                             private_key) -> str:
        """
        Decrypt a secure message with multiple layers.
        
        Args:
            secure_message: The encrypted message structure
            private_key: RSA private key for decryption
            
        Returns:
            The decrypted plaintext message
        """
        # Extract session key using RSA private key
        encrypted_session_key = secure_message['encrypted_session_key']
        session_password = self.cm.rsa_decrypt(encrypted_session_key, private_key)
        
        # Decrypt the main message using AES
        aes_data = secure_message['aes_encrypted_data']
        decrypted_message = self.cm.aes_decrypt(
            aes_data['ciphertext'],
            session_password,
            aes_data['salt'],
            aes_data['iv']
        )
        
        # Verify checksum
        if self._calculate_checksum(decrypted_message) != secure_message['checksum']:
            raise ValueError("Message integrity check failed!")
        
        return decrypted_message
    
    def _calculate_checksum(self, message: str) -> str:
        """Calculate SHA-256 checksum of message."""
        return hashlib.sha256(message.encode()).hexdigest()

def benchmark_encryption_algorithms():
    """Benchmark different encryption algorithms."""
    print("=== Encryption Algorithm Benchmark ===")
    
    cm = CryptoManager()
    test_data = "This is a test message for benchmarking encryption algorithms. " * 10
    
    algorithms = [
        ("Caesar Cipher", lambda: cm.caesar_encrypt(test_data, 3)),
        ("XOR Cipher", lambda: cm.xor_encrypt(test_data, "benchmark_key")),
        ("Vigenère Cipher", lambda: cm.vigenere_encrypt(test_data, "BENCHMARK")),
        ("AES-256", lambda: cm.aes_encrypt(test_data, "benchmark_password")),
        ("Fernet", lambda: cm.fernet_encrypt(test_data)),
        ("RC4", lambda: cm.rc4_encrypt(test_data, "benchmark_key")),
        ("Rail Fence", lambda: cm.railfence_encrypt(test_data, 5))
    ]
    
    results = []
    for name, func in algorithms:
        start_time = time.time()
        try:
            result = func()
            end_time = time.time()
            duration = (end_time - start_time) * 1000  # Convert to milliseconds
            results.append((name, duration, "Success"))
        except Exception as e:
            results.append((name, 0, f"Error: {str(e)}"))
    
    # Print results
    print(f"{'Algorithm':<20} {'Time (ms)':<12} {'Status':<15}")
    print("-" * 50)
    for name, duration, status in results:
        print(f"{name:<20} {duration:<12.2f} {status:<15}")
    print()

def demonstrate_key_rotation():
    """Demonstrate key rotation for enhanced security."""
    print("=== Key Rotation Demonstration ===")
    
    cm = CryptoManager()
    message = "Sensitive data that needs key rotation"
    
    # Generate multiple key pairs
    keys = []
    for i in range(3):
        private_key, public_key = cm.generate_rsa_keys()
        keys.append((f"Key Pair {i+1}", private_key, public_key))
    
    # Encrypt with different keys
    encrypted_messages = []
    for name, private_key, public_key in keys:
        encrypted = cm.rsa_encrypt(message, public_key)
        encrypted_messages.append((name, encrypted, private_key))
    
    # Decrypt with corresponding keys
    for name, encrypted, private_key in encrypted_messages:
        decrypted = cm.rsa_decrypt(encrypted, private_key)
        print(f"{name}: {decrypted}")
    
    print()

def demonstrate_error_handling():
    """Demonstrate proper error handling in cryptography."""
    print("=== Error Handling Demonstration ===")
    
    cm = CryptoManager()
    
    # Test wrong password for AES
    try:
        result = cm.aes_encrypt("test", "password1")
        wrong_decrypt = cm.aes_decrypt(
            result['ciphertext'],
            "wrong_password",
            result['salt'],
            result['iv']
        )
        print(f"AES wrong password result: {wrong_decrypt}")
    except Exception as e:
        print(f"AES error handling: {e}")
    
    # Test invalid rail count
    try:
        result = cm.railfence_encrypt("test", 1)
        print(f"Rail fence invalid rails: {result}")
    except Exception as e:
        print(f"Rail fence error handling: {e}")
    
    # Test RSA with wrong key
    try:
        private_key1, public_key1 = cm.generate_rsa_keys()
        private_key2, public_key2 = cm.generate_rsa_keys()
        
        encrypted = cm.rsa_encrypt("test", public_key1)
        wrong_decrypt = cm.rsa_decrypt(encrypted, private_key2)
        print(f"RSA wrong key result: {wrong_decrypt}")
    except Exception as e:
        print(f"RSA error handling: {e}")
    
    print()

def demonstrate_file_encryption_simulation():
    """Simulate file encryption/decryption patterns."""
    print("=== File Encryption Simulation ===")
    
    cm = CryptoManager()
    
    # Simulate file content
    file_content = """
    This is a simulated file content.
    It contains multiple lines of text.
    We'll encrypt this as if it were a real file.
    """
    
    # Encrypt file content
    password = "file_encryption_password"
    result = cm.aes_encrypt(file_content, password)
    
    # Simulate saving encrypted file
    encrypted_file_data = {
        'header': 'CRYPTOMANAGER_ENCRYPTED_FILE',
        'version': '1.0',
        'algorithm': 'AES-256',
        'ciphertext': result['ciphertext'],
        'salt': result['salt'],
        'iv': result['iv']
    }
    
    # Simulate file metadata
    file_metadata = {
        'original_filename': 'document.txt',
        'encryption_date': time.time(),
        'file_size': len(file_content),
        'checksum': hashlib.sha256(file_content.encode()).hexdigest()
    }
    
    print(f"Original file size: {len(file_content)} bytes")
    print(f"Encrypted data size: {len(result['ciphertext'])} bytes")
    print(f"File metadata: {json.dumps(file_metadata, indent=2)}")
    
    # Decrypt file content
    decrypted_content = cm.aes_decrypt(
        result['ciphertext'],
        password,
        result['salt'],
        result['iv']
    )
    
    print(f"Decrypted content matches original: {decrypted_content == file_content}")
    print()

def main():
    """Run all advanced examples."""
    print("🔐 CryptoManager - Advanced Usage Examples\n")
    
    # Benchmark algorithms
    benchmark_encryption_algorithms()
    
    # Demonstrate key rotation
    demonstrate_key_rotation()
    
    # Demonstrate error handling
    demonstrate_error_handling()
    
    # Demonstrate secure message handling
    print("=== Secure Message Handling ===")
    handler = SecureMessageHandler()
    
    # Generate keys for demonstration
    private_key, public_key = handler.cm.generate_rsa_keys()
    
    # Create secure message
    message = "This is a highly secure message with multiple encryption layers."
    session_password = "temporary_session_key_123"
    
    secure_message = handler.create_secure_message(message, public_key, session_password)
    print(f"Secure message created with {len(secure_message)} layers of protection")
    
    # Decrypt secure message
    decrypted_message = handler.decrypt_secure_message(secure_message, private_key)
    print(f"Message decrypted successfully: {decrypted_message}")
    print()
    
    # Demonstrate file encryption simulation
    demonstrate_file_encryption_simulation()
    
    print("✅ All advanced examples completed successfully!")

if __name__ == "__main__":
    main() 