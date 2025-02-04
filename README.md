# Password Manager

A **secure** and **simple** password manager built with Python. This project encrypts stored passwords using the **Fernet symmetric encryption** method and secures them with a master password.

---

## 🔒 Features

- Secure password encryption using **Fernet (AES-128)**
- **Master password** protection with key derivation (`PBKDF2HMAC`)
- Ability to **add, view, and overwrite** stored passwords
- Automatic encryption key management
- Uses a **.gitignore** to prevent sensitive files from being tracked

---

## 📌 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPO.git
cd Password-Manager
```

### 2️⃣ Install Dependencies
Ensure you have **Python 3.6+** installed, then install required packages:
```bash
pip install cryptography
```

### 3️⃣ Run the Password Manager
```bash
python password_manager.py
```

---

## 📜 How It Works

### 🔑 Encryption & Security
- A **master password** is used to derive a secure encryption key using **PBKDF2HMAC**.
- The program securely stores **login credentials** (`account | encrypted password`) in `passwords.txt`.
- Encryption key is stored in `key.key`, and a **random salt** is used (`salt.bin`).

### 📂 File Structure
```
📂 Password Manager
│── password_manager.py  # Main script
│── key.key              # Encryption key (DO NOT SHARE)
│── salt.bin             # Salt for key derivation
│── passwords.txt        # Encrypted stored passwords
│── .gitignore           # Prevents tracking of sensitive files
│── README.md            # Project documentation
```

---

## ⚠️ Important Notes
1. **DO NOT** share your `key.key` or `salt.bin` files! Losing them means **losing access** to your stored passwords.
2. The `.gitignore` file prevents sensitive files from being pushed to GitHub.
3. Each time you start the program, you must enter the **correct master password**.

---

## 🚀 Usage Guide

### ➕ Adding a Password
1. Run the program:  
   ```bash
   python password_manager.py
   ```
2. Select `'a'` to add a new password.
3. Enter the **account name** and **password**.
4. Password will be securely stored.

### 👀 Viewing Stored Passwords
1. Run the program.
2. Select `'v'` to view stored passwords.
3. The program will decrypt and display them.

### ❌ Exiting the Program
- Press `'q'` to **quit**.

---

## 🛠 Recommended `.gitignore`
Ensure that `.gitignore` includes:
```
__pycache__/
*.pyc
*.pyo
*.pyd
.DS_Store
Thumbs.db
.env
key.key
salt.bin
*.log
```

---

## 📜 License
This project is **open-source** under the [MIT License](LICENSE).

---

## 💡 Future Improvements
- Add **GUI interface** using Tkinter or PyQt
- Implement a **password generator**
- Secure key storage with **hardware encryption (TPM)**

---

## 👤 Author
- **Reese Ludwick**
- GitHub: [@reese8272](https://github.com/reese8272)

---

