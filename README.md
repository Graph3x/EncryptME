# EncryptME
A simple program for file encryption with remotely stored keys. It uses Fernet to encrypt files, Fernet and RSA(PKCS1_OAEP) to encrypt communication with server and salted pbkdf2 to hash passwords. Make sure to generate your own RSA keys, you can use "generate_rsa.py" or any other method.

WARNING: This is a work in progress so I would recommend against using it on important files. It is also using Fernet which doesn't handle well large files!
Dependencies:
- Cryptography
- Cryptodome
- PyQt5
- easygui
- tkinter
