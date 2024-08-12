from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import io
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.http import MediaIoBaseDownload
import pandas as pd

class Crypt:
    def __init__(self, key, old_salt=None):
        self.salt =  old_salt if old_salt else Fernet.generate_key()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
            backend=default_backend()
        )

        handler = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        
        self.f = Fernet(handler)

    def encrypt_password(self, password):
        encrypted_password = self.f.encrypt(password.encode()).decode()
        return encrypted_password

    def decrypt_password(self, encrypted_password):
        decrypted_password = self.f.decrypt(encrypted_password).decode()
        return decrypted_password
    
class GoogleDriveHandler:
    def __init__(self, token, client_id, client_secret):
        self.creds = Credentials(
            token=token['access_token'],
            refresh_token=token['refresh_token'],
            token_uri="https://oauth2.googleapis.com/token",
            client_id=client_id,
            client_secret=client_secret
        )
        self.service = build('drive', 'v3', credentials=self.creds)

        self.folder_name='Encrypto'
        self.folder_id=self._get_folder_id()
        self.filename='encrypto.csv'

        

    def _get_folder_id(self):
        """Check if the folder exists; if not, create it."""
        query = f"name='{self.folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
        results = self.service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
        items = results.get('files', [])

        if not items:
            # Folder doesn't exist, create it
            folder_metadata = {
                'name': self.folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            folder = self.service.files().create(body=folder_metadata, fields='id').execute()
            return folder.get('id')
        else:
            # Folder exists
            return items[0]['id']

    def _check_file_exists(self):
        """Check if the file exists in the given folder."""

        query = f"'{self.folder_id}' in parents and name='{self.filename}' and trashed=false"
        results = self.service.files().list(q=query, spaces='drive', fields='files(id)').execute()
        items = results.get('files', [])
        return items[0]['id'] if items else None

    def save_binary_to_drive(self, binary_data):
        """Save binary data to Google Drive as a file, replacing if it exists."""
        file_id = self._check_file_exists()
        if file_id:
            # File exists, delete it
            self.service.files().delete(fileId=file_id).execute()

        # Convert the binary data to a buffer and upload to Google Drive
        binary_buffer = io.BytesIO(binary_data)
        binary_buffer.seek(0)

        file_metadata = {'name': self.filename, 'parents': [self.folder_id]}
        media = MediaIoBaseUpload(binary_buffer, mimetype='application/octet-stream', resumable=True)
        file = self.service.files().create(body=file_metadata, media_body=media, fields='id').execute()

        return file.get('id')


    def read_file_from_drive(self):
        """Read a file from Google Drive by filename."""
        file_id = self._check_file_exists()
        
        if not file_id:
            raise FileNotFoundError(f"File '{self.filename}' not found in folder '{self.folder_name}'.")

        # Download the file
        request = self.service.files().get_media(fileId=file_id)
        file_content = io.BytesIO()
        downloader = MediaIoBaseDownload(file_content, request)
        
        done = False
        while done is False:
            status, done = downloader.next_chunk()
            print(f"Download {int(status.progress() * 100)}%.")

        file_content.seek(0)

        # Convert the file content to a DataFrame
        return pd.read_csv(file_content)