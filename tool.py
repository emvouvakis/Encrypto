from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Crypt:
    def __init__(self, key, old_salt=None):
        self.salt =  old_salt if old_salt else Fernet.generate_key()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=390000,
            backend=default_backend()
        )
        self.handler = base64.urlsafe_b64encode(kdf.derive(key.encode()))

    def encrypt_password(self, password):
        f = Fernet(self.handler)
        encrypted_password = f.encrypt(password.encode()).decode()
        return encrypted_password

    def decrypt_password(self, encrypted_password):
        f = Fernet(self.handler)
        decrypted_password = f.decrypt(encrypted_password).decode()
        return decrypted_password