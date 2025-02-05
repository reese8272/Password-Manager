import sqlite3
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from hashlib import sha256

# Initialize SQLite database
conn = sqlite3.connect("passwords.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS passwords (
    account TEXT PRIMARY KEY,
    encrypted_password TEXT
)
""")
conn.commit()

# Function to load or generate the encryption key
def load_key():
    """
    This function checks if the key file ('key.key') exists. 
    If the file doesn't exist, it generates a new Fernet key, saves it to 'key.key', 
    and returns the generated key.
    If the file exists, it loads and returns the key stored in 'key.key'.
    """
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        return key
    else:
        with open("key.key", "rb") as file:
            return file.read()

# Function to derive master key
def derive_master_key(master_password, salt):
    """
    This function derives a key from the user's master password and a random salt 
    using the PBKDF2 key derivation function. It uses SHA256 for the hash and 
    performs 1,000,000 iterations to make the key generation more secure.
    The resulting key is base64 encoded to make it suitable for Fernet encryption.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

# Load key and initialize encryption
key = load_key()

# Master password input
master_password = input("Enter your master password: ")

# Load or generate salt
if not os.path.exists("salt.bin"):
    salt = os.urandom(16)
    with open("salt.bin", "wb") as salt_file:
        salt_file.write(salt)
else:
    with open("salt.bin", "rb") as salt_file:
        salt = salt_file.read()

master_key = derive_master_key(master_password, salt)
combined_key = sha256(key + master_key).digest()
final_key = base64.urlsafe_b64encode(combined_key)
fer = Fernet(final_key)

# Function to view stored passwords
def view():
    """
    This function retrieves and decrypts stored passwords from the SQLite database.
    If no passwords are found, it notifies the user.
    """
    cursor.execute("SELECT * FROM passwords")
    rows = cursor.fetchall()
    if not rows:
        print("No saved passwords found.")
        return
    for account, encrypted_pass in rows:
        try:
            decrypted_pass = fer.decrypt(encrypted_pass.encode()).decode()
            print(f"Account: {account}, Password: {decrypted_pass}")
        except Exception as e:
            print(f"Error decrypting password for {account}: {e}")

# Function to add/update passwords
def add():
    """
    This function prompts the user for an account name and password, encrypts the password,
    and stores it in the SQLite database. If the account already exists, it asks for confirmation
    before overwriting.
    """
    account = input("Account Name: ")
    cursor.execute("SELECT * FROM passwords WHERE account = ?", (account,))
    existing_entry = cursor.fetchone()
    
    if existing_entry:
        confirm = input(f"Account '{account}' already exists. Overwrite? (y/n): ").strip().lower()
        if confirm != 'y':
            return
    
    password = input("Password: ")
    encrypted_password = fer.encrypt(password.encode()).decode()
    cursor.execute("REPLACE INTO passwords (account, encrypted_password) VALUES (?, ?)", (account, encrypted_password))
    conn.commit()
    print("Password saved successfully.")

# Main loop
while True:
    """
    This loop runs continuously, asking the user whether they want to add a password, 
    view existing ones, or quit. The loop will break if the user enters 'q' to quit.
    """
    mode = input("Would you like to add a password or view existing ones? (a to add, v to view, q to quit): ").lower()
    if mode == "q":
        break
    elif mode == "v":
        view()
    elif mode == "a":
        add()
    else:
        print("Invalid input. Please try again.")

conn.close()