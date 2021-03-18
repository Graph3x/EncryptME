# EncryptME
A simple program for file encryption with remotely stored keys. It uses Fernet to encrypt files, Fernet and RSA(PKCS1_OAEP) to encrypt communication with server and salted pbkdf2 to hash passwords. Make sure to generate your own RSA keys, you can use "generate_rsa.py" or any other method.

WARNING: This is a buggy POC, do not use it on important files! It is also not optimized for big files, so please do not try to encrypt anything big with it.

Dependencies:
- Cryptography
- Cryptodome
- PyQt5
- easygui
- tkinter
