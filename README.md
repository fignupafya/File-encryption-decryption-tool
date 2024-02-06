# File Encryption and Decryption Tool

This Python script provides a simple command-line interface for encrypting and decrypting files using the Fernet symmetric encryption algorithm from the `cryptography` library. It allows users to securely protect their sensitive files with a password and decrypt them when needed.

## Features

- Encrypts files using a user-provided password.
- Decrypts encrypted files with the correct password.
- Supports hiding encrypted files and salt file for added security.

## Usage

1. Ensure you have Python 3.x installed on your system.

2. Download the script file `encrypt_decrypt.py` to your local machine.

3. To encrypt a file, simply double-click on the `encrypt_decrypt.py` file. It will prompt you to enter a password. After entering the password, press Enter.

4. To decrypt a file, again, double-click on the `encrypt_decrypt.py` file. It will ask for your password. Enter the password and press Enter.

5. Encrypted files will have the extension `.encrypted` appended to their filenames.

## Notes

- Ensure you remember your password as it is required for decryption.
- Safely store the salt file `.salt.key` generated during encryption.
- Safe files (`lock-unlock.py` and `.salt.key`) are not encrypted for convenience and accessibility.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
