import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key,
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import getpass

class CryptoManager:
    # 1. Caesar Cipher
    @staticmethod
    def caesar_encrypt(plaintext: str, shift: int) -> str:
        encrypted = []
        shift = shift % 26
        for char in plaintext:
            if char.isalpha():
                offset = ord('A') if char.isupper() else ord('a')
                encrypted_char = chr((ord(char) - offset + shift) % 26 + offset)
                encrypted.append(encrypted_char)
            else:
                encrypted.append(char)
        return ''.join(encrypted)

    @staticmethod
    def caesar_decrypt(ciphertext: str, shift: int) -> str:
        return CryptoManager.caesar_encrypt(ciphertext, -shift)

    # 2. XOR Cipher
    @staticmethod
    def xor_encrypt(plaintext: str, key: str) -> str:
        key_bytes = key.encode()
        encrypted_bytes = bytearray()
        for i, byte in enumerate(plaintext.encode()):
            encrypted_bytes.append(byte ^ key_bytes[i % len(key_bytes)])
        return base64.urlsafe_b64encode(encrypted_bytes).decode()

    @staticmethod
    def xor_decrypt(ciphertext: str, key: str) -> str:
        try:
            encrypted_bytes = base64.urlsafe_b64decode(ciphertext)
            key_bytes = key.encode()
            decrypted_bytes = bytearray()
            for i, byte in enumerate(encrypted_bytes):
                decrypted_bytes.append(byte ^ key_bytes[i % len(key_bytes)])
            return decrypted_bytes.decode()
        except Exception as e:
            return f"Decryption failed: {str(e)}"

    # 3. Vigenère Cipher
    @staticmethod
    def vigenere_encrypt(plaintext: str, key: str) -> str:
        key = key.upper()
        encrypted = []
        key_index = 0
        for char in plaintext:
            if char.isalpha():
                offset = ord('A') if char.isupper() else ord('a')
                key_char = ord(key[key_index % len(key)]) - ord('A')
                encrypted_char = chr((ord(char) - offset + key_char) % 26 + offset)
                encrypted.append(encrypted_char)
                key_index += 1
            else:
                encrypted.append(char)
        return ''.join(encrypted)

    @staticmethod
    def vigenere_decrypt(ciphertext: str, key: str) -> str:
        key = key.upper()
        decrypted = []
        key_index = 0
        for char in ciphertext:
            if char.isalpha():
                offset = ord('A') if char.isupper() else ord('a')
                key_char = ord(key[key_index % len(key)]) - ord('A')
                decrypted_char = chr((ord(char) - offset - key_char) % 26 + offset)
                decrypted.append(decrypted_char)
                key_index += 1
            else:
                decrypted.append(char)
        return ''.join(decrypted)

    # 4. AES-256
    @staticmethod
    def aes_encrypt(plaintext: str, password: str) -> dict:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode()
        }

    @staticmethod
    def aes_decrypt(ciphertext: str, password: str, salt: str, iv: str) -> str:
        try:
            salt = base64.b64decode(salt)
            iv = base64.b64decode(iv)
            ciphertext = base64.b64decode(ciphertext)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            return decrypted.decode()
        except Exception as e:
            return f"Decryption failed: {str(e)}"

    # 5. RSA
    @staticmethod
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    @staticmethod
    def rsa_encrypt(plaintext: str, public_key) -> str:
        try:
            ciphertext = public_key.encrypt(
                plaintext.encode(),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            return f"Encryption failed: {str(e)}"

    @staticmethod
    def rsa_decrypt(ciphertext: str, private_key) -> str:
        try:
            ciphertext = base64.b64decode(ciphertext)
            plaintext = private_key.decrypt(
                ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode()
        except Exception as e:
            return f"Decryption failed: {str(e)}"

    # 6. Fernet
    @staticmethod
    def fernet_encrypt(plaintext: str) -> dict:
        key = Fernet.generate_key()
        f = Fernet(key)
        ciphertext = f.encrypt(plaintext.encode())
        return {
            'ciphertext': ciphertext.decode(),
            'key': key.decode()
        }

    @staticmethod
    def fernet_decrypt(ciphertext: str, key: str) -> str:
        try:
            f = Fernet(key.encode())
            return f.decrypt(ciphertext.encode()).decode()
        except Exception as e:
            return f"Decryption failed: {str(e)}"

    # 7. Triple DES
    @staticmethod
    def triple_des_encrypt(plaintext: str, password: str) -> dict:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=24,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        iv = os.urandom(8)
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode()
        }

    @staticmethod
    def triple_des_decrypt(ciphertext: str, password: str, salt: str, iv: str) -> str:
        try:
            salt = base64.b64decode(salt)
            iv = base64.b64decode(iv)
            ciphertext = base64.b64decode(ciphertext)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=24,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(64).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            return decrypted.decode()
        except Exception as e:
            return f"Decryption failed: {str(e)}"

    # 8. Blowfish
    @staticmethod
    def blowfish_encrypt(plaintext: str, password: str) -> dict:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        iv = os.urandom(8)  # Blowfish uses 8-byte IV
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.Blowfish(key[:32]), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode()
        }

    @staticmethod
    def blowfish_decrypt(ciphertext: str, password: str, salt: str, iv: str) -> str:
        try:
            salt = base64.b64decode(salt)
            iv = base64.b64decode(iv)
            ciphertext = base64.b64decode(ciphertext)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            cipher = Cipher(algorithms.Blowfish(key[:32]), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(64).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            return decrypted.decode()
        except Exception as e:
            return f"Decryption failed: {str(e)}"

    # 9. RC4
    @staticmethod
    def rc4_encrypt(plaintext: str, key: str) -> str:
        try:
            S = list(range(256))
            j = 0
            key_bytes = key.encode()
            for i in range(256):
                j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
                S[i], S[j] = S[j], S[i]
            i = j = 0
            encrypted_bytes = bytearray()
            plaintext_bytes = plaintext.encode()
            for byte in plaintext_bytes:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                k = S[(S[i] + S[j]) % 256]
                encrypted_bytes.append(byte ^ k)
            return base64.urlsafe_b64encode(encrypted_bytes).decode()
        except Exception as e:
            return f"Encryption failed: {str(e)}"

    @staticmethod
    def rc4_decrypt(ciphertext: str, key: str) -> str:
        try:
            encrypted_bytes = base64.urlsafe_b64decode(ciphertext)
            S = list(range(256))
            j = 0
            key_bytes = key.encode()
            for i in range(256):
                j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
                S[i], S[j] = S[j], S[i]
            i = j = 0
            decrypted_bytes = bytearray()
            for byte in encrypted_bytes:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                k = S[(S[i] + S[j]) % 256]
                decrypted_bytes.append(byte ^ k)
            return decrypted_bytes.decode()
        except Exception as e:
            return f"Decryption failed: {str(e)}"

    # 10. Rail Fence
    @staticmethod
    def railfence_encrypt(plaintext: str, rails: int) -> str:
        if rails < 2:
            return "Number of rails must be at least 2"
            
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in plaintext:
            fence[rail].append(char)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
            
        encrypted = ''.join([''.join(rail) for rail in fence])
        return encrypted

    @staticmethod
    def railfence_decrypt(ciphertext: str, rails: int) -> str:
        if rails < 2:
            return "Number of rails must be at least 2"
            
        length = len(ciphertext)
        fence = [[] for _ in range(rails)]
        rail_lengths = [0] * rails
        
        # Calculate the length of each rail
        rail = 0
        direction = 1
        for _ in range(length):
            rail_lengths[rail] += 1
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        
        # Populate the fence with characters from the ciphertext
        index = 0
        for i in range(rails):
            fence[i] = list(ciphertext[index:index + rail_lengths[i]])
            index += rail_lengths[i]
        
        # Read the message in zigzag pattern
        rail = 0
        direction = 1
        decrypted = []
        for _ in range(length):
            decrypted.append(fence[rail].pop(0))
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
            
        return ''.join(decrypted)

def main():
    cm = CryptoManager()
    methods = {
        '1': 'Caesar',
        '2': 'XOR',
        '3': 'Vigenère',
        '4': 'AES',
        '5': 'RSA',
        '6': 'Fernet',
        '7': 'Triple DES',
        '8': 'Blowfish',
        '9': 'RC4',
        '10': 'Rail Fence'
    }

    while True:
        print("\n=== Cryptography Manager ===")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Generate RSA Keys")
        print("4. Exit")
        choice = input("Select option: ")

        if choice == '4':
            print("Exiting program...")
            break

        if choice == '1':
            print("Available encryption methods:")
            for key, value in methods.items():
                print(f"{key}. {value}")
            method = input("Select encryption method: ")
            plaintext = input("Enter text to encrypt: ")

            if method == '1':  # Caesar
                shift = int(input("Enter shift value (1-25): "))
                print(f"\nEncrypted Text: {cm.caesar_encrypt(plaintext, shift)}")

            elif method == '2':  # XOR
                key = input("Enter XOR key: ")  # Changed from getpass to input for testing
                print(f"\nEncrypted Text: {cm.xor_encrypt(plaintext, key)}")

            elif method == '3':  # Vigenère
                key = input("Enter Vigenère key: ")  # Changed from getpass to input for testing
                print(f"\nEncrypted Text: {cm.vigenere_encrypt(plaintext, key)}")

            elif method == '4':  # AES
                password = input("Enter encryption password: ")  # Changed from getpass to input for testing
                result = cm.aes_encrypt(plaintext, password)
                print("\nEncrypted Text:", result['ciphertext'])
                print("Salt:", result['salt'])
                print("IV:", result['iv'])

            elif method == '5':  # RSA
                try:
                    # Generate keys if they don't exist for testing purposes
                    if not (os.path.exists('public_key.pem') and os.path.exists('private_key.pem')):
                        print("RSA keys not found. Generating new keys...")
                        private_key, public_key = cm.generate_rsa_keys()
                        priv_pem = private_key.private_bytes(
                            Encoding.PEM,
                            PrivateFormat.PKCS8,
                            NoEncryption()
                        )
                        pub_pem = public_key.public_bytes(
                            Encoding.PEM,
                            PublicFormat.SubjectPublicKeyInfo
                        )
                        with open('private_key.pem', 'wb') as f:
                            f.write(priv_pem)
                        with open('public_key.pem', 'wb') as f:
                            f.write(pub_pem)
                        print("Keys generated and saved as private_key.pem and public_key.pem")

                    public_key_path = input("Enter public key file path (default: public_key.pem): ") or "public_key.pem"
                    with open(public_key_path, 'rb') as f:
                        public_key = load_pem_public_key(f.read(), backend=default_backend())
                    print(f"\nEncrypted Text: {cm.rsa_encrypt(plaintext, public_key)}")
                except Exception as e:
                    print(f"Error: {str(e)}")

            elif method == '6':  # Fernet
                result = cm.fernet_encrypt(plaintext)
                print("\nEncrypted Text:", result['ciphertext'])
                print("Fernet Key:", result['key'])

            elif method == '7':  # Triple DES
                password = input("Enter encryption password: ")  # Changed from getpass to input for testing
                result = cm.triple_des_encrypt(plaintext, password)
                print("\nEncrypted Text:", result['ciphertext'])
                print("Salt:", result['salt'])
                print("IV:", result['iv'])

            elif method == '8':  # Blowfish
                password = input("Enter encryption password: ")  # Changed from getpass to input for testing
                result = cm.blowfish_encrypt(plaintext, password)
                print("\nEncrypted Text:", result['ciphertext'])
                print("Salt:", result['salt'])
                print("IV:", result['iv'])

            elif method == '9':  # RC4
                key = input("Enter RC4 key: ")  # Changed from getpass to input for testing
                print(f"\nEncrypted Text: {cm.rc4_encrypt(plaintext, key)}")

            elif method == '10':  # Rail Fence
                rails = int(input("Enter number of rails (2-10): "))
                print(f"\nEncrypted Text: {cm.railfence_encrypt(plaintext, rails)}")

            else:
                print("Invalid method selection!")

        elif choice == '2':
            print("Available decryption methods:")
            for key, value in methods.items():
                print(f"{key}. {value}")
            method = input("Select decryption method: ")
            ciphertext = input("Enter ciphertext: ")

            if method == '1':  # Caesar
                shift = int(input("Enter shift value (1-25): "))
                print(f"\nDecrypted Text: {cm.caesar_decrypt(ciphertext, shift)}")

            elif method == '2':  # XOR
                key = input("Enter XOR key: ")  # Changed from getpass to input for testing
                print(f"\nDecrypted Text: {cm.xor_decrypt(ciphertext, key)}")

            elif method == '3':  # Vigenère
                key = input("Enter Vigenère key: ")  # Changed from getpass to input for testing
                print(f"\nDecrypted Text: {cm.vigenere_decrypt(ciphertext, key)}")

            elif method == '4':  # AES
                password = input("Enter decryption password: ")  # Changed from getpass to input for testing
                salt = input("Enter salt: ")
                iv = input("Enter IV: ")
                try:
                    print(f"\nDecrypted Text: {cm.aes_decrypt(ciphertext, password, salt, iv)}")
                except Exception as e:
                    print(f"Decryption failed: {str(e)}")

            elif method == '5':  # RSA
                private_key_path = input("Enter private key file path (default: private_key.pem): ") or "private_key.pem"
                try:
                    with open(private_key_path, 'rb') as f:
                        private_key = load_pem_private_key(
                            f.read(),
                            password=None,
                            backend=default_backend()
                        )
                    print(f"\nDecrypted Text: {cm.rsa_decrypt(ciphertext, private_key)}")
                except Exception as e:
                    print(f"Error: {str(e)}")

            elif method == '6':  # Fernet
                key = input("Enter Fernet key: ")  # Changed from getpass to input for testing
                try:
                    print(f"\nDecrypted Text: {cm.fernet_decrypt(ciphertext, key)}")
                except Exception as e:
                    print(f"Decryption failed: {str(e)}")

            elif method == '7':  # Triple DES
                password = input("Enter decryption password: ")  # Changed from getpass to input for testing
                salt = input("Enter salt: ")
                iv = input("Enter IV: ")
                try:
                    print(f"\nDecrypted Text: {cm.triple_des_decrypt(ciphertext, password, salt, iv)}")
                except Exception as e:
                    print(f"Decryption failed: {str(e)}")

            elif method == '8':  # Blowfish
                password = input("Enter decryption password: ")  # Changed from getpass to input for testing
                salt = input("Enter salt: ")
                iv = input("Enter IV: ")
                try:
                    print(f"\nDecrypted Text: {cm.blowfish_decrypt(ciphertext, password, salt, iv)}")
                except Exception as e:
                    print(f"Decryption failed: {str(e)}")

            elif method == '9':  # RC4
                key = input("Enter RC4 key: ")  # Changed from getpass to input for testing
                print(f"\nDecrypted Text: {cm.rc4_decrypt(ciphertext, key)}")

            elif method == '10':  # Rail Fence
                rails = int(input("Enter number of rails used: "))
                print(f"\nDecrypted Text: {cm.railfence_decrypt(ciphertext, rails)}")

            else:
                print("Invalid method selection!")

        elif choice == '3':
            private_key, public_key = cm.generate_rsa_keys()
            priv_pem = private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption()
            )
            pub_pem = public_key.public_bytes(
                Encoding.PEM,
                PublicFormat.SubjectPublicKeyInfo
            )
            with open('private_key.pem', 'wb') as f:
                f.write(priv_pem)
            with open('public_key.pem', 'wb') as f:
                f.write(pub_pem)
            print("\nRSA keys generated and saved as:")
            print("- private_key.pem")
            print("- public_key.pem")

        else:
            print("Invalid option selected!")

if __name__ == "__main__":
    main()