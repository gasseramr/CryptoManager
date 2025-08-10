import unittest
import sys
import os
import tempfile
import shutil

# Add the parent directory to the path to import CryptoManager
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from CryptoManager import CryptoManager

class TestCryptoManager(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.cm = CryptoManager()
        self.test_text = "Hello, World! 123"
        self.test_key = "test_key_123"
        self.test_password = "secure_password_456"
        
        # Create temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up after each test method."""
        # Remove temporary directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        # Clean up any generated key files
        for key_file in ['private_key.pem', 'public_key.pem']:
            if os.path.exists(key_file):
                os.remove(key_file)

    def test_caesar_cipher(self):
        """Test Caesar cipher encryption and decryption."""
        shift = 3
        encrypted = self.cm.caesar_encrypt(self.test_text, shift)
        decrypted = self.cm.caesar_decrypt(encrypted, shift)
        
        self.assertNotEqual(self.test_text, encrypted)
        self.assertEqual(self.test_text, decrypted)
        
        # Test with different shift values
        for shift in [1, 5, 10, 25]:
            encrypted = self.cm.caesar_encrypt(self.test_text, shift)
            decrypted = self.cm.caesar_decrypt(encrypted, shift)
            self.assertEqual(self.test_text, decrypted)

    def test_xor_cipher(self):
        """Test XOR cipher encryption and decryption."""
        encrypted = self.cm.xor_encrypt(self.test_text, self.test_key)
        decrypted = self.cm.xor_decrypt(encrypted, self.test_key)
        
        self.assertNotEqual(self.test_text, encrypted)
        self.assertEqual(self.test_text, decrypted)
        
        # Test with different keys
        keys = ["key1", "longer_key_123", "special!@#$%"]
        for key in keys:
            encrypted = self.cm.xor_encrypt(self.test_text, key)
            decrypted = self.cm.xor_decrypt(encrypted, key)
            self.assertEqual(self.test_text, decrypted)

    def test_vigenere_cipher(self):
        """Test Vigenère cipher encryption and decryption."""
        key = "SECRET"
        encrypted = self.cm.vigenere_encrypt(self.test_text, key)
        decrypted = self.cm.vigenere_decrypt(encrypted, key)
        
        self.assertNotEqual(self.test_text, encrypted)
        self.assertEqual(self.test_text, decrypted)
        
        # Test with different keys
        keys = ["ABC", "CRYPTO", "KEY"]
        for key in keys:
            encrypted = self.cm.vigenere_encrypt(self.test_text, key)
            decrypted = self.cm.vigenere_decrypt(encrypted, key)
            self.assertEqual(self.test_text, decrypted)

    def test_aes_encryption(self):
        """Test AES-256 encryption and decryption."""
        result = self.cm.aes_encrypt(self.test_text, self.test_password)
        
        # Check that result contains required fields
        self.assertIn('ciphertext', result)
        self.assertIn('salt', result)
        self.assertIn('iv', result)
        
        # Test decryption
        decrypted = self.cm.aes_decrypt(
            result['ciphertext'],
            self.test_password,
            result['salt'],
            result['iv']
        )
        
        self.assertEqual(self.test_text, decrypted)
        
        # Test with different passwords
        passwords = ["password1", "secure_pass", "test123"]
        for password in passwords:
            result = self.cm.aes_encrypt(self.test_text, password)
            decrypted = self.cm.aes_decrypt(
                result['ciphertext'],
                password,
                result['salt'],
                result['iv']
            )
            self.assertEqual(self.test_text, decrypted)

    def test_rsa_encryption(self):
        """Test RSA encryption and decryption."""
        # Generate keys
        private_key, public_key = self.cm.generate_rsa_keys()
        
        # Test encryption and decryption
        encrypted = self.cm.rsa_encrypt(self.test_text, public_key)
        decrypted = self.cm.rsa_decrypt(encrypted, private_key)
        
        self.assertNotEqual(self.test_text, encrypted)
        self.assertEqual(self.test_text, decrypted)
        
        # Test with longer text (RSA has limitations)
        long_text = "This is a longer message to test RSA encryption capabilities."
        encrypted = self.cm.rsa_encrypt(long_text, public_key)
        decrypted = self.cm.rsa_decrypt(encrypted, private_key)
        self.assertEqual(long_text, decrypted)

    def test_fernet_encryption(self):
        """Test Fernet encryption and decryption."""
        result = self.cm.fernet_encrypt(self.test_text)
        
        # Check that result contains required fields
        self.assertIn('ciphertext', result)
        self.assertIn('key', result)
        
        # Test decryption
        decrypted = self.cm.fernet_decrypt(result['ciphertext'], result['key'])
        self.assertEqual(self.test_text, decrypted)

    def test_triple_des_encryption(self):
        """Test Triple DES encryption and decryption."""
        result = self.cm.triple_des_encrypt(self.test_text, self.test_password)
        
        # Check that result contains required fields
        self.assertIn('ciphertext', result)
        self.assertIn('salt', result)
        self.assertIn('iv', result)
        
        # Test decryption
        decrypted = self.cm.triple_des_decrypt(
            result['ciphertext'],
            self.test_password,
            result['salt'],
            result['iv']
        )
        
        self.assertEqual(self.test_text, decrypted)

    def test_blowfish_encryption(self):
        """Test Blowfish encryption and decryption."""
        result = self.cm.blowfish_encrypt(self.test_text, self.test_password)
        
        # Check that result contains required fields
        self.assertIn('ciphertext', result)
        self.assertIn('salt', result)
        self.assertIn('iv', result)
        
        # Test decryption
        decrypted = self.cm.blowfish_decrypt(
            result['ciphertext'],
            self.test_password,
            result['salt'],
            result['iv']
        )
        
        self.assertEqual(self.test_text, decrypted)

    def test_rc4_encryption(self):
        """Test RC4 encryption and decryption."""
        encrypted = self.cm.rc4_encrypt(self.test_text, self.test_key)
        decrypted = self.cm.rc4_decrypt(encrypted, self.test_key)
        
        self.assertNotEqual(self.test_text, encrypted)
        self.assertEqual(self.test_text, decrypted)
        
        # Test with different keys
        keys = ["key1", "longer_key_123", "special!@#$%"]
        for key in keys:
            encrypted = self.cm.rc4_encrypt(self.test_text, key)
            decrypted = self.cm.rc4_decrypt(encrypted, key)
            self.assertEqual(self.test_text, decrypted)

    def test_rail_fence_encryption(self):
        """Test Rail Fence encryption and decryption."""
        rails = 3
        encrypted = self.cm.railfence_encrypt(self.test_text, rails)
        decrypted = self.cm.railfence_decrypt(encrypted, rails)
        
        self.assertNotEqual(self.test_text, encrypted)
        self.assertEqual(self.test_text, decrypted)
        
        # Test with different rail counts
        for rails in [2, 4, 5, 10]:
            encrypted = self.cm.railfence_encrypt(self.test_text, rails)
            decrypted = self.cm.railfence_decrypt(encrypted, rails)
            self.assertEqual(self.test_text, decrypted)

    def test_edge_cases(self):
        """Test edge cases for various algorithms."""
        # Empty string
        empty_text = ""
        self.assertEqual(empty_text, self.cm.caesar_decrypt(
            self.cm.caesar_encrypt(empty_text, 3), 3
        ))
        
        # Special characters
        special_text = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        self.assertEqual(special_text, self.cm.caesar_decrypt(
            self.cm.caesar_encrypt(special_text, 5), 5
        ))
        
        # Unicode characters
        unicode_text = "Hello 世界! 🌍"
        self.assertEqual(unicode_text, self.cm.xor_decrypt(
            self.cm.xor_encrypt(unicode_text, "key"), "key"
        ))

    def test_error_handling(self):
        """Test error handling for invalid inputs."""
        # Test invalid rail count
        result = self.cm.railfence_encrypt("test", 1)
        self.assertIn("Number of rails must be at least 2", result)
        
        # Test decryption with wrong key
        encrypted = self.cm.xor_encrypt("test", "key1")
        decrypted = self.cm.xor_decrypt(encrypted, "key2")
        self.assertNotEqual("test", decrypted)
        
        # Test AES decryption with wrong password
        result = self.cm.aes_encrypt("test", "password1")
        decrypted = self.cm.aes_decrypt(
            result['ciphertext'],
            "wrong_password",
            result['salt'],
            result['iv']
        )
        self.assertIn("Decryption failed", decrypted)

    def test_rsa_key_generation(self):
        """Test RSA key generation."""
        private_key, public_key = self.cm.generate_rsa_keys()
        
        # Test that keys are different
        self.assertNotEqual(private_key, public_key)
        
        # Test that keys can be used for encryption/decryption
        test_message = "Test message"
        encrypted = self.cm.rsa_encrypt(test_message, public_key)
        decrypted = self.cm.rsa_decrypt(encrypted, private_key)
        self.assertEqual(test_message, decrypted)

    def test_algorithm_consistency(self):
        """Test that algorithms produce consistent results with same inputs."""
        # Test Caesar cipher consistency
        text = "Hello"
        shift = 3
        result1 = self.cm.caesar_encrypt(text, shift)
        result2 = self.cm.caesar_encrypt(text, shift)
        self.assertEqual(result1, result2)
        
        # Test XOR consistency
        key = "test_key"
        result1 = self.cm.xor_encrypt(text, key)
        result2 = self.cm.xor_encrypt(text, key)
        self.assertEqual(result1, result2)

if __name__ == '__main__':
    unittest.main() 