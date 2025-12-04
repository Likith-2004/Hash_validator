# HΞX – Secure File Encryption & Integrity Suite

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/PyQt6-Desktop_GUI-green?style=for-the-badge&logo=qt&logoColor=white)](https://riverbankcomputing.com/software/pyqt/)
[![Security](https://img.shields.io/badge/AES--256--GCM-Military_Grade-orange?style=for-the-badge&logo=shield&logoColor=white)](https://cryptography.io/)
[![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)](LICENSE)

**HΞX** is a powerful, cross-platform desktop security suite built to democratize access to military-grade cryptography. It combines a modern, dark-themed GUI with robust backend logic to handle file encryption, integrity verification, and secure password hashing without the complexity of command-line tools.

---

## 🚀 Features

### 🔐 File Encryption & Decryption
- **Algorithm:** Uses **AES-256-GCM** (Galois/Counter Mode) for Authenticated Encryption.
- **Security:** Derives distinct 256-bit keys for every file using **PBKDF2-HMAC-SHA256** with random 16-byte Salts.
- **Integrity:** Automatically verifies authentication tags during decryption to detect tampering.

### 📂 Batch Folder Hashing
- **Multi-threaded:** Processes thousands of files recursively without freezing the UI.
- **Real-time:** Live progress bar and status logs.
- **Algorithms:** Supports MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512.

### 🛡️ Integrity Verification
- **Tamper Detection:** Instantly compares a file's actual hash against an expected checksum.
- **Visual Feedback:** Color-coded alerts (Green for Match, Red for Mismatch).
- **Smart Detection:** Auto-detects algorithm type based on hash length.

### 🔑 Password Lab
- **Next-Gen Hashing:** Generates and verifies hashes using **Argon2id** (winner of the Password Hashing Competition).
- **Legacy Support:** Includes support for `bcrypt` and `PBKDF2` for compatibility testing.

### 🎨 Modern Experience
- **Drag & Drop:** Custom widget support for dropping files/folders directly from Explorer.
- **Dark Mode:** Professional slate-grey theme with neon accents (#00BFA6).
- **Audit Trail:** JSON-based history logging for all cryptographic operations.

---

## 🛠️ Installation

### Prerequisites
- Python 3.10 or higher
- pip (Python Package Manager)

### Setup

#### 1. Clone the Repository
```bash
git clone https://github.com/Likith-2004/Hash_validator.git
cd Hash_validator
```

#### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

Key libraries installed: PyQt6, cryptography, argon2-cffi, bcrypt, qtawesome.

#### 3. Run the Application
```bash
python hash_validator.py
```

---

## 🏗️ Repository Structure
```
Hash_validator/
├── hash_validator.py       # Main Application Entry Point
├── requirements.txt        # Python Dependencies
├── static/
│   ├── logo.png            # App Icon
│   └── screenshots/        # Images for README
├── .file_validator_history.json  # Local History Log (Auto-generated)
└── README.md               # Documentation
```

---

## 🧩 Technical Architecture

The application follows a Controller-Worker architecture to ensure responsiveness:

- **Frontend (View):** Built with PyQt6, utilizing QStackedWidget for navigation and Custom QSS for styling.

- **Concurrency:** Heavy I/O tasks (like hashing 10GB ISOs) are offloaded to threading.Thread workers to prevent the Main GUI Thread from blocking.

- **Crypto Engine:**
  - Encryption: `cryptography.hazmat.primitives.ciphers.modes.GCM`
  - Key Derivation: `cryptography.hazmat.primitives.kdf.pbkdf2`
  - Hashing: `hashlib` (SHA-3) & `argon2`

---

## 🤝 Contributing

Contributions are welcome! Please fork this repository and submit a pull request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
