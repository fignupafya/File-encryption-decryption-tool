import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

SAFE_FILES = ['lock-unlock.py', 'salt.key']

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def save_salt_to_file(salt, filename):
    with open(filename, 'wb') as salt_file:
        salt_file.write(salt)

def load_salt_from_file(filename):
    with open(filename, 'rb') as salt_file:
        return salt_file.read()

def encrypt_decrypt_file(password, input_file, output_file, encrypt=True):
    if input_file in SAFE_FILES:
        return

    salt_file = 'salt.key'
    if os.path.exists(salt_file):
        salt = load_salt_from_file(salt_file)
    else:
        salt = os.urandom(16)
        save_salt_to_file(salt, salt_file)

    key = derive_key(password, salt)

    if encrypt:
        output_file = f"{input_file}.encrypted"
    else:
        if input_file.endswith('.encrypted'):
            output_file = output_file.replace('.encrypted', '')
        else:
            print(f"Cannot decrypt {input_file}. File is not encrypted.")
            return

    with open(input_file, 'rb') as file:
        data = file.read()

    fernet = Fernet(key)
    if encrypt:
        encrypted_data = fernet.encrypt(data)

        # Delete the decrypted file after encryption
        os.remove(input_file)
    else:
        try:
            encrypted_data = fernet.decrypt(data)

            # Delete the encrypted file after decryption
            os.remove(input_file)

        except:
            print(f"Failed to decrypt {input_file}. Invalid password?")
            return

    with open(output_file, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

def is_all_decrypted():
    current_directory = os.getcwd()
    for filename in os.listdir(current_directory):
        if filename.endswith(".encrypted"):
            return False
    return True

def main():
    decrypt = not is_all_decrypted()

    password = input("Enter your password: ")

    if not decrypt:
        password2 = input("Enter your password again: ")
        if password != password2:
            print("Passwords do not match.")
            return

    for filename in os.listdir('.'):
        if filename not in SAFE_FILES:
            if filename.endswith('.encrypted') and decrypt:
                encrypt_decrypt_file(password, filename, filename, encrypt=False)
                print(f"{filename} decrypted and encrypted successfully!")
            elif not filename.endswith('.encrypted') and not decrypt:
                encrypt_decrypt_file(password, filename, filename, encrypt=True)
                print(f"{filename} encrypted and decrypted successfully!")

    if decrypt and is_all_decrypted():
        os.remove("salt.key")

if __name__ == "__main__":
    main()
