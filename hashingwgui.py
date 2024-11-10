import hashlib
import os
import binascii
import tkinter as tk
from tkinter import messagebox

def hash_password(password, salt=None, iterations=100000):
    """
    Hash a password using PBKDF2 with SHA-256 and a salt.
    A unique salt is generated if not provided.
    """
    if not salt:
        salt = os.urandom(16)  # Generate a 16-byte random salt
    
    # Generate the PBKDF2 hash of the password
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',               # Hash algorithm
        password.encode('utf-8'),  # Password as bytes
        salt,                   # Salt
        iterations              # Number of iterations
    )
    
    # Convert the hash to a hexadecimal format
    password_hash_hex = binascii.hexlify(password_hash).decode('utf-8')
    
    return salt, password_hash_hex

def verify_password(stored_password_hash, password_attempt, salt, iterations=100000):
    """
    Verify if the provided password attempt matches the stored password hash.
    """
    attempt_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password_attempt.encode('utf-8'),
        salt,
        iterations
    )
    attempt_hash_hex = binascii.hexlify(attempt_hash).decode('utf-8')
    
    return stored_password_hash == attempt_hash_hex

# GUI setup
def on_hash_password():
    user_id = entry_user_id.get()
    password = entry_password.get()

    if user_id and password:
        salt, password_hash = hash_password(password)
        output_salt.config(text=f"Salt (hex): {salt.hex()}")
        output_hash.config(text=f"Password Hash: {password_hash}")
        global stored_salt, stored_password_hash
        stored_salt = salt
        stored_password_hash = password_hash
        messagebox.showinfo("Success", "Password hashed and stored successfully!")
    else:
        messagebox.showwarning("Input Error", "Please enter both user ID and password.")

def on_verify_password():
    password_attempt = entry_verify_password.get()

    if stored_password_hash and password_attempt:
        is_valid = verify_password(stored_password_hash, password_attempt, stored_salt)
        if is_valid:
            messagebox.showinfo("Verification", "Password is valid!")
        else:
            messagebox.showerror("Verification", "Invalid password.")
    else:
        messagebox.showwarning("Input Error", "No stored password or input provided.")

# Main Tkinter window
root = tk.Tk()
root.title("Secure Password Hashing")
root.geometry("500x400")

# Labels and input fields
tk.Label(root, text="User ID:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
entry_user_id = tk.Entry(root, width=30)
entry_user_id.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
entry_password = tk.Entry(root, show="*", width=30)
entry_password.grid(row=1, column=1, padx=10, pady=10)

tk.Button(root, text="Hash Password", command=on_hash_password).grid(row=2, column=1, pady=10)

tk.Label(root, text="Re-enter Password to Verify:").grid(row=3, column=0, padx=10, pady=10, sticky="w")
entry_verify_password = tk.Entry(root, show="*", width=30)
entry_verify_password.grid(row=3, column=1, padx=10, pady=10)

tk.Button(root, text="Verify Password", command=on_verify_password).grid(row=4, column=1, pady=10)

# Output labels
output_salt = tk.Label(root, text="Salt (hex): ")
output_salt.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="w")

output_hash = tk.Label(root, text="Password Hash: ")
output_hash.grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky="w")

# Global variables for storage
stored_salt = None
stored_password_hash = None

# Start the Tkinter event loop
root.mainloop()
