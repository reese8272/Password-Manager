from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from hashlib import sha256

# Function to load the encryption key from file
def load_key():
    """
    This function checks if the key file ('key.key') exists. 
    If the file doesn't exist, it generates a new Fernet key, saves it to 'key.key', 
    and returns the generated key.
    If the file exists, it loads and returns the key stored in 'key.key'.
    """
    if not os.path.exists("key.key"):
        print("Key file not found! Generating a new key...")
        key = Fernet.generate_key()  # Generate a new key using Fernet
        with open("key.key", "wb") as key_file:  # Write the generated key to 'key.key'
            key_file.write(key)
        print("New key generated and saved.")
        return key
    else:
        with open("key.key", "rb") as file:  # Load the existing key from 'key.key'
            return file.read()

# Function to derive a key from the master password using PBKDF2
def derive_master_key(master_password, salt):
    """
    This function derives a key from the user's master password and a random salt 
    using the PBKDF2 key derivation function. It uses SHA256 for the hash and 
    performs 1,000,000 iterations to make the key generation more secure.
    The resulting key is base64 encoded to make it suitable for Fernet encryption.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key
        salt=salt,  # The salt to be used in the key derivation
        iterations=1000000  # Number of iterations for increased security
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))  # Return the base64 encoded key

# Initialize the key from "key.key"
key = load_key()

# Prompt user for the master password
master_password = input("Enter your master password: ")

# Derive a key from the master password and the salt (reuse the same salt for consistency)
if not os.path.exists("salt.bin"):  # If salt file doesn't exist, generate and save it
    salt = os.urandom(16)  # Generate a random 16-byte salt
    with open("salt.bin", "wb") as salt_file:  # Save the salt to 'salt.bin'
        salt_file.write(salt)
else:
    with open("salt.bin", "rb") as salt_file:  # Load the salt from 'salt.bin'
        salt = salt_file.read()

master_key = derive_master_key(master_password, salt)

# Combine the loaded key and the master key using SHA256 to ensure it's 32 bytes
combined_key = sha256(key + master_key).digest()  # Hash the concatenation of the Fernet key and master key

# Initialize Fernet cipher with the final key
final_key = base64.urlsafe_b64encode(combined_key)  # Base64 encode the final key
fer = Fernet(final_key)  # Create a Fernet instance with the final key

# Function to view stored passwords
def view():
    """
    This function reads the 'passwords.txt' file and attempts to decrypt and print 
    the stored passwords. If decryption fails for a specific line, it will display an error message.
    """
    try:
        with open('passwords.txt', 'r') as f:
            for line in f:
                data = line.strip()  # Strip any whitespace characters
                try:
                    user, encrypted_pass = data.split("|")  # Split the line into account name and encrypted password
                    decrypted_pass = fer.decrypt(encrypted_pass.encode()).decode()  # Decrypt the password
                    print(f"User: {user}, Password: {decrypted_pass}")  # Print the decrypted account info
                except Exception as e:
                    print(f"Error decrypting line: {data} -> {e}")  # If decryption fails, print an error
    except FileNotFoundError:
        print("No saved passwords found.")  # If 'passwords.txt' is missing, notify the user

# Function to check for existing accounts and ask for overwrite
def overwrite(name):
    """
    This function checks if the given account name already exists in 'passwords.txt'. 
    If it exists, it asks the user if they want to overwrite the existing password.
    If the user chooses not to overwrite, it returns False.
    """
    try:
        with open('passwords.txt', 'r') as file:
            names = {line.split("|")[0] for line in file}  # Collect all account names from the file
        if name in names:  # If the account exists
            answer = input(f"Account '{name}' already exists. Overwrite? (y/n) -> ").strip().lower()
            return answer == 'y'  # If user agrees to overwrite, return True
        return True  # If the account doesn't exist, allow adding a new one
    except FileNotFoundError:
        return True  # If 'passwords.txt' is missing, allow adding new entries

# Function to add or overwrite passwords
def add():
    """
    This function adds a new password or overwrites an existing one. 
    It prompts the user for the account name and password, 
    encrypts the password, and writes it to 'passwords.txt'.
    """
    name = input("Account Name: ")
    if overwrite(name):  # Check if it's okay to overwrite the account
        pwd = input("Password: ")

        lines = []
        # Read all lines into memory to perform overwrite
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()

        # Check if the account name exists and remove it if overwriting
        with open('passwords.txt', 'w') as file:
            for line in lines:
                user, _ = line.strip().split("|")  # Split the line into account and password
                if user != name:  # Only write the lines that don't match the account to be overwritten
                    file.write(line)
            
            # After overwriting (or adding), append the new or modified entry
            encrypted_pwd = fer.encrypt(pwd.encode()).decode()  # Encrypt the password
            file.write(f"{name}|{encrypted_pwd}\n")  # Save the account name and encrypted password to the file
        print("Password saved successfully.")  # Notify the user that the password was saved

# Main loop
while True:
    """
    This loop runs continuously, asking the user whether they want to add a password, 
    view existing ones, or quit. The loop will break if the user enters 'q' to quit.
    """
    mode = input("Would you like to add a password, or view your existing ones? (press 'a' to add, 'v' to view, or 'q' to quit) -> ").lower()
    if mode == "q":
        break  # Exit the loop and end the program
    elif mode == "v":
        view()  # Call the view function to display stored passwords
    elif mode == "a":
        add()  # Call the add function to add a new password
    else:
        print("Invalid input. Please try again.")  # Prompt the user again for valid input
