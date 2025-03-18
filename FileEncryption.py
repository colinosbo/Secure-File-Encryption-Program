import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hashlib
import base64
import os


# Generate key from password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


# Encrypt and replace original file
def encrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        original_hash = hashlib.sha256(data).hexdigest()

        salt = os.urandom(16)
        key = generate_key(password, salt)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)

        # Overwrite original file with salt + encrypted data
        with open(file_path, 'wb') as f:
            f.write(salt + encrypted)
        # Save hash in a separate file
        with open(file_path + '.hash', 'w') as f:
            f.write(original_hash)
        return original_hash
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        return None


# Decrypt and restore original the file
def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            encrypted = f.read()

        key = generate_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        new_hash = hashlib.sha256(decrypted).hexdigest()

        # Overwrite file with decrypted content
        with open(file_path, 'wb') as f:
            f.write(decrypted)
        return decrypted.decode(), new_hash
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        return None, None


# GUI
root = tk.Tk()
root.title("Secure File Encryptor By Colin Osborn")
root.geometry("500x400")
root.resizable(True, True)

file_path = ""
original_hash = ""


# Choosing a File
def choose_file():
    global file_path
    file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
    if file_path:
        file_label.config(text=f"Selected: {file_path.split('/')[-1]}")

tk.Label(root, text="Choose a file", font=("Arial", 12)).pack(pady=5)
tk.Button(root, text="Browse", command=choose_file).pack(pady=5)
file_label = tk.Label(root, text="No file selected", wraplength=450)
file_label.pack(pady=5)

# Password entry
tk.Label(root, text="Enter password", font=("Arial", 12)).pack(pady=5)
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=5)

# Output display
output_text = tk.Text(root, height=6, width=50, wrap="word")
output_text.pack(pady=10)


# Encrypt button
def encrypt():
    global file_path, original_hash
    if not file_path or not password_entry.get():
        messagebox.showerror("Error", "Please select a file and enter a password!")
        return
    original_hash = encrypt_file(file_path, password_entry.get())
    if original_hash:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, f"File encrypted in place!\nOriginal hash: {original_hash[:10]}... (saved)")


tk.Button(root, text="Encrypt File", command=encrypt, bg="green", fg="white").pack(pady=5)


# Decrypt button
def decrypt():
    global file_path, original_hash
    if not file_path or not password_entry.get():
        messagebox.showerror("Error", "Please select a file and enter a password!")
        return

    content, new_hash = decrypt_file(file_path, password_entry.get())
    if content is not None:
        try:
            with open(file_path + '.hash', 'r') as f:
                original_hash = f.read().strip()
        except FileNotFoundError:
            messagebox.showwarning("Warning", "Original hash file not found!")
            original_hash = "Unknown"

        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END,
                           f"Decrypted content: {content[:50]}...\nNew hash: {new_hash[:10]}...\nOriginal hash: {original_hash[:10]}...")
        if new_hash == original_hash:
            messagebox.showinfo("Success", "Hash matches—file restored!")
        else:
            messagebox.showwarning("Warning", "Hash mismatch—tampered or wrong password!")


tk.Button(root, text="Decrypt File", command=decrypt, bg="blue", fg="white").pack(pady=5)

# Run the GUI
root.mainloop()