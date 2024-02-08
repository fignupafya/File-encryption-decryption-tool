# File Encryption and Decryption Tool

This Python script provides a simple command-line interface for encrypting and decrypting files using the Fernet symmetric encryption algorithm from the `cryptography` library. It allows users to securely protect their sensitive files with a password and decrypt them when needed.
Can be used to keep a journal.

## Features

- Encrypts files using a user-provided password.
- Decrypts encrypted files with the correct password.
- Supports hiding encrypted files and salt file for added security.

## Requirements

1. Ensure you have Python 3.x installed on your system. If not, you can download and install it from [python.org](https://www.python.org/downloads/).

2. Install the required dependency using pip:

    ```
    pip install cryptography
    ```




## Usage

1. Download the script file `encrypt_decrypt.py` to your local machine.

2. To encrypt a file, simply double-click on the `encrypt_decrypt.py` file. It will prompt you to enter a password. After entering the password, press Enter.

3. To decrypt a file, again, double-click on the `encrypt_decrypt.py` file. It will ask for your password. Enter the password and press Enter.

4. Encrypted files will have the extension `.encrypted` appended to their filenames.

## Notes

- Ensure you remember your password as it is required for decryption.
- Safely store the salt file `.salt.key` generated during encryption.
- Safe files (`lock-unlock.py` and `.salt.key`) are not encrypted for convenience and accessibility.

