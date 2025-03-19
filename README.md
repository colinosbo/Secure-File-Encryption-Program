# Secure File Encryptor

Secure File Encryptor is a Python-based desktop application that allows users to encrypt and decrypt files using a password. The application employs strong cryptographic techniques to secure your files and verifies integrity using SHA-256 hashing. Built with a simple GUI using Tkinter, it’s user-friendly and efficient for personal file security.

---

## Features
- **File Encryption**: Encrypts any file type using a password-derived key.
- **File Decryption**: Decrypts files and verifies their integrity against the original hash.
- **Hash Verification**: Stores the original file’s SHA-256 hash to ensure the file hasn’t been tampered with after decryption.
- **In-Place Encryption**: Overwrites the original file with encrypted data to save space.
- **Simple GUI**: Built with Tkinter for an intuitive user experience.

---

## How It Works

### Encryption Process
1. **File Selection**: The user selects a file via the "Browse" button.
2. **Password Input**: The user enters a password, which is used to derive an encryption key.
3. **Key Generation**: A random 16-byte salt is generated, and the password is processed with PBKDF2-HMAC (SHA-256, 100,000 iterations) to create a secure 32-byte key.
4. **Encryption**: The file’s contents are encrypted using the Fernet symmetric encryption scheme from the `cryptography` library.
5. **Hash Storage**: The original file’s SHA-256 hash is calculated and saved in a separate `.hash` file.
6. **File Overwrite**: The original file is replaced with the salt + encrypted data.

### Decryption Process
1. **File Selection**: The user selects the encrypted file.
2. **Password Input**: The user enters the same password used for encryption.
3. **Key Regeneration**: The salt is extracted from the file, and the key is regenerated using PBKDF2-HMAC.
4. **Decryption**: The encrypted data is decrypted using Fernet.
5. **Integrity Check**: The decrypted file’s SHA-256 hash is compared to the stored original hash to verify integrity.
6. **File Restoration**: The decrypted content overwrites the encrypted file.

### Security Features
- Uses PBKDF2 with a high iteration count to make key derivation resistant to brute-force attacks.
- Employs Fernet (AES-128 in CBC mode with PKCS7 padding + HMAC-SHA256) for encryption.
- Includes salt to ensure unique keys even with the same password.

---

## Visual Demonstration

This section shows the Secure File Encryptor in action, walking through the process of selecting, encrypting, and decrypting a file.

1. **Initial File Selection**: Select a file (e.g., `test.txt`) and enter a password to prepare for encryption. The file’s original content is shown on the right.  
   ![Initial file selection](images/initial-selection.png)

2. **Encryption**: After clicking "Encrypt File," the file is encrypted in place, and the original hash is saved. The file’s content is now unreadable encrypted data.  
   ![Encryption process](images/encryption-process.png)

3. **Decryption and Verification**: After selecting the encrypted file and entering the password, click "Decrypt File." The file is decrypted, and a success message confirms the hash matches, verifying integrity. The original content is restored.  
   ![Decryption and verification](images/decryption-verification.png)

---

## Technologies Used
- **Python 3**: Core programming language.
- **Tkinter**: Standard Python library for creating the graphical user interface (GUI).
- **Cryptography**: Python library for secure encryption and key derivation (`Fernet`, `PBKDF2`).
