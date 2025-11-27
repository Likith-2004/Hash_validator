#!/usr/bin/env python3
# File: file_validator_complete.py
# App : HΞX – Secure File & Password Hashing/Encryption Suite
# Enhanced: full algorithm support, PBKDF2 with random salt, threaded folder hashing,
# structured history, copy-to-clipboard, robust logo integration, DRAG & DROP SUPPORT,
# and AES-256-GCM File Encryption/Decryption.

import os
import sys
import json
import hashlib
import hmac
import bcrypt
import pathlib
import threading
import base64
from functools import partial
from datetime import datetime
from argon2 import PasswordHasher

# New Imports for Encryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QFileDialog,
    QStackedWidget, QFrame, QStatusBar, QComboBox, QListWidget, QListWidgetItem,
    QProgressBar, QMessageBox
)
from PyQt6.QtGui import QIcon, QDragEnterEvent, QDropEvent
from PyQt6.QtCore import Qt, QUrl
import qtawesome as qta

APP_NAME = "HΞX"
HISTORY_FILE = os.path.expanduser("~/.file_validator_history.json")
PALETTE = {
    "bg": "#101010",
    "card": "#181818",
    "border": "#2e2e2e",
    "text": "#e0e0e0",
    "accent": "#00BFA6",
    "danger": "#E57373",
    "success": "#81C784",
    "hover": "#252525"
}

def qss():
    return f"""
    QWidget {{
        background-color: {PALETTE['bg']};
        color: {PALETTE['text']};
        font-family: 'Segoe UI', sans-serif;
        font-size: 13px;
    }}
    QPushButton {{
        background-color: {PALETTE['card']};
        border: 1px solid {PALETTE['border']};
        border-radius: 6px;
        padding: 8px 12px;
    }}
    QPushButton:hover {{
        border-color: {PALETTE['accent']};
        color: {PALETTE['accent']};
    }}
    QLineEdit, QTextEdit {{
        background-color: {PALETTE['card']};
        border: 1px solid {PALETTE['border']};
        border-radius: 6px;
        padding: 6px;
        color: {PALETTE['text']};
    }}
    QLineEdit[dragHover=true] {{
        border: 2px dashed {PALETTE['accent']};
        background-color: {PALETTE['hover']};
    }}
    QComboBox {{
        background-color: {PALETTE['card']};
        border: 1px solid {PALETTE['border']};
        border-radius: 6px;
        padding: 5px;
        color: {PALETTE['text']};
    }}
    QListWidget {{
        background-color: {PALETTE['card']};
        border: 1px solid {PALETTE['border']};
        border-radius: 6px;
    }}
    QStatusBar {{
        background-color: {PALETTE['card']};
        color: {PALETTE['accent']};
    }}
    """

# === DRAG & DROP LINE EDIT WIDGET ===
class DropLineEdit(QLineEdit):
    def __init__(self, parent=None, accept_files=True, accept_folders=False):
        super().__init__(parent)
        self.accept_files = accept_files
        self.accept_folders = accept_folders
        self.setAcceptDrops(True)
        self.setDragEnabled(False)
        self.setProperty("dragHover", False)
        self.setStyleSheet("")

    def dragEnterEvent(self, event: QDragEnterEvent):
        if not event.mimeData().hasUrls():
            event.ignore()
            return

        urls = event.mimeData().urls()
        if not urls:
            event.ignore()
            return

        path = urls[0].toLocalFile()
        if not os.path.exists(path):
            event.ignore()
            return

        is_dir = os.path.isdir(path)
        if (self.accept_files and os.path.isfile(path)) or (self.accept_folders and is_dir):
            event.acceptProposedAction()
            self.setProperty("dragHover", True)
            self.style().unpolish(self)
            self.style().polish(self)
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.setProperty("dragHover", False)
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event: QDropEvent):
        self.setProperty("dragHover", False)
        self.style().unpolish(self)
        self.style().polish(self)

        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        if os.path.exists(path):
            self.setText(path)
            event.acceptProposedAction()

# === MAIN WINDOW ===
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.history = self._load_history()
        self.hash_alg = "SHA-256"
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1150, 700)
        self.setStyleSheet(qss())
        self.nav_buttons = []
        self.stop_flag = False
        self._build_ui()

    def _build_ui(self):
        main = QWidget()
        layout = QHBoxLayout(main)
        layout.setContentsMargins(0, 0, 0, 0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setFixedWidth(230)
        sidebar.setStyleSheet(f"background-color: {PALETTE['card']}; border-right: 1px solid {PALETTE['border']};")
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(10, 10, 10, 10)

        logo = QLabel(APP_NAME)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet(f"color: {PALETTE['accent']}; font-size: 18px; font-weight: bold; margin-bottom: 15px;")
        side_layout.addWidget(logo)

        nav_items = [
            ("file", "Single File"),
            ("folder", "Folder"),
            ("key", "Password Hashing"),
            ("lock", "Encrypt/Decrypt"), # NEW PAGE
            ("history", "History"),
            ("shield-alt", "Integrity Check"),
        ]
        for idx, (icon, text) in enumerate(nav_items):
            btn = QPushButton(qta.icon(f'fa5s.{icon}', color=PALETTE['accent']), f" {text}")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(partial(self._switch_tab, idx))
            self.nav_buttons.append(btn)
            side_layout.addWidget(btn)
        side_layout.addStretch(1)

        # Main stack
        self.stack = QStackedWidget()
        self.pages = [
            self._page_single(),
            self._page_folder(),
            self._page_password(),
            self._page_encryption(), # NEW PAGE METHOD
            self._page_history(),
            self._page_integrity(),
        ]
        for p in self.pages:
            self.stack.addWidget(p)

        self.status = QStatusBar()
        self.setStatusBar(self.status)

        layout.addWidget(sidebar)
        layout.addWidget(self.stack)
        self.setCentralWidget(main)
        self._switch_tab(0)

    def _switch_tab(self, index):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.setStyleSheet(f"border-color:{PALETTE['accent']}; color:{PALETTE['accent']};")
            else:
                btn.setStyleSheet(f"border:1px solid {PALETTE['border']}; color:{PALETTE['text']};")
        self.status.showMessage(f"Switched to {self.nav_buttons[index].text().strip()}")

    def _page_single(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addWidget(QLabel("<b>Single File Hashing</b>"))

        self.algo_box = QComboBox()
        self.algo_box.addItems(["MD5", "SHA1", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512"])
        self.algo_box.setCurrentText("SHA-256")
        self.algo_box.currentTextChanged.connect(lambda x: setattr(self, "hash_alg", x))
        layout.addWidget(self.algo_box)

        self.path_edit = DropLineEdit(accept_files=True, accept_folders=False)
        self.path_edit.setPlaceholderText("Drop file here or click Browse...")
        browse = QPushButton("Browse")
        browse.clicked.connect(self._select_file)
        hl = QHBoxLayout()
        hl.addWidget(self.path_edit)
        hl.addWidget(browse)
        layout.addLayout(hl)

        self.result = QTextEdit()
        self.result.setReadOnly(True)
        layout.addWidget(self.result)

        run_row = QHBoxLayout()
        run = QPushButton("Compute Hash")
        run.clicked.connect(self._validate_file)
        copy_btn = QPushButton("Copy Hash")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.result.toPlainText()))
        run_row.addWidget(run)
        run_row.addWidget(copy_btn)
        layout.addLayout(run_row)
        return page

    def _page_folder(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addWidget(QLabel("<b>Folder Hashing</b>"))

        self.folder_edit = DropLineEdit(accept_files=False, accept_folders=True)
        self.folder_edit.setPlaceholderText("Drop folder here or click Browse...")
        browse = QPushButton("Browse")
        browse.clicked.connect(self._select_folder)
        hl = QHBoxLayout()
        hl.addWidget(self.folder_edit)
        hl.addWidget(browse)
        layout.addLayout(hl)

        self.folder_result = QTextEdit()
        self.folder_result.setReadOnly(True)
        layout.addWidget(self.folder_result)

        self.folder_progress = QProgressBar()
        layout.addWidget(self.folder_progress)

        run_row = QHBoxLayout()
        run = QPushButton("Hash All Files")
        run.clicked.connect(self._start_folder_hash)
        stop_btn = QPushButton("Stop")
        stop_btn.clicked.connect(self._stop_folder_hash)
        run_row.addWidget(run)
        run_row.addWidget(stop_btn)
        layout.addLayout(run_row)
        return page

    def _page_password(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addWidget(QLabel("<b>Password Hashing & Verification</b>"))

        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setPlaceholderText("Enter password...")
        layout.addWidget(self.pass_input)

        self.pass_algo = QComboBox()
        self.pass_algo.addItems(["Argon2", "bcrypt", "PBKDF2"])
        layout.addWidget(self.pass_algo)

        run = QPushButton("Generate Hash")
        run.clicked.connect(self._hash_password)
        layout.addWidget(run)

        layout.addWidget(QLabel("Generated Hash:"))
        self.pass_result = QTextEdit()
        self.pass_result.setReadOnly(True)
        layout.addWidget(self.pass_result)

        copy_btn = QPushButton("Copy Hash")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.pass_result.toPlainText()))
        layout.addWidget(copy_btn)

        layout.addWidget(QLabel("Verify Password:"))
        self.verify_input = QLineEdit()
        self.verify_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.verify_input.setPlaceholderText("Enter password to verify...")
        layout.addWidget(self.verify_input)

        verify_btn = QPushButton("Verify Password")
        verify_btn.clicked.connect(self._verify_password)
        layout.addWidget(verify_btn)

        self.verify_result = QLabel("")
        layout.addWidget(self.verify_result)
        return page

    # --- NEW ENCRYPTION PAGE ---
    def _page_encryption(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addWidget(QLabel("<b>File Encryption (AES-256-GCM)</b>"))

        # --- Password Input ---
        layout.addWidget(QLabel("Secret Password (Key Derivation):"))
        self.enc_pass_input = QLineEdit()
        self.enc_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.enc_pass_input.setPlaceholderText("Enter a strong password for the key...")
        layout.addWidget(self.enc_pass_input)

        # --- File Input ---
        layout.addWidget(QLabel("Input File:"))
        self.enc_input_edit = DropLineEdit(accept_files=True, accept_folders=False)
        self.enc_input_edit.setPlaceholderText("Drop file here to encrypt/decrypt...")
        browse_in = QPushButton("Browse Input")
        browse_in.clicked.connect(lambda: self._select_any_file(self.enc_input_edit))
        
        hl_in = QHBoxLayout()
        hl_in.addWidget(self.enc_input_edit)
        hl_in.addWidget(browse_in)
        layout.addLayout(hl_in)

        # --- Output Path ---
        layout.addWidget(QLabel("Output File Path:"))
        self.enc_output_edit = QLineEdit()
        self.enc_output_edit.setPlaceholderText("Enter output path...")
        browse_out = QPushButton("Browse Output")
        browse_out.clicked.connect(self._select_save_file)
        
        hl_out = QHBoxLayout()
        hl_out.addWidget(self.enc_output_edit)
        hl_out.addWidget(browse_out)
        layout.addLayout(hl_out)

        # --- Action Buttons ---
        btn_row = QHBoxLayout()
        enc_btn = QPushButton(qta.icon('fa5s.lock', color=PALETTE['accent']), " Encrypt File")
        enc_btn.clicked.connect(self._handle_encrypt)
        dec_btn = QPushButton(qta.icon('fa5s.unlock', color=PALETTE['accent']), " Decrypt File")
        dec_btn.clicked.connect(self._handle_decrypt)
        
        btn_row.addWidget(enc_btn)
        btn_row.addWidget(dec_btn)
        layout.addLayout(btn_row)

        # --- Result Display ---
        self.enc_result = QLabel("")
        layout.addWidget(self.enc_result)
        layout.addStretch(1)
        return page
    # --- END NEW ENCRYPTION PAGE ---

    def _page_history(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addWidget(QLabel("<b>Hashing History</b>"))

        self.history_list = QListWidget()
        layout.addWidget(self.history_list)
        self._refresh_history_ui()

        btn_row = QHBoxLayout()
        clear_btn = QPushButton("Clear History")
        clear_btn.clicked.connect(self._clear_history)
        export_btn = QPushButton("Export History")
        export_btn.clicked.connect(self._export_history)
        import_btn = QPushButton("Import History")
        import_btn.clicked.connect(self._import_history)
        btn_row.addWidget(clear_btn)
        btn_row.addWidget(export_btn)
        btn_row.addWidget(import_btn)
        layout.addLayout(btn_row)
        return page

    def _page_integrity(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addWidget(QLabel("<b>Integrity Check</b>"))

        self.check_file_edit = DropLineEdit(accept_files=True, accept_folders=False)
        self.check_file_edit.setPlaceholderText("Drop file here or click Browse...")
        browse = QPushButton("Browse")
        browse.clicked.connect(self._select_check_file)
        hl = QHBoxLayout()
        hl.addWidget(self.check_file_edit)
        hl.addWidget(browse)
        layout.addLayout(hl)

        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter expected hash...")
        layout.addWidget(self.hash_input)

        run = QPushButton("Verify Integrity")
        run.clicked.connect(self._check_integrity)
        layout.addWidget(run)

        self.check_output = QLabel("")
        layout.addWidget(self.check_output)
        return page

    # File dialogs (updated with a generic one)
    def _select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.path_edit.setText(path)
            
    def _select_any_file(self, line_edit):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            line_edit.setText(path)

    def _select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.folder_edit.setText(folder)

    def _select_check_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.check_file_edit.setText(path)
            
    def _select_save_file(self):
        # Determine the default name based on input
        input_file = self.enc_input_edit.text()
        if input_file:
            base, ext = os.path.splitext(input_file)
            if ext.lower() == ".enc":
                default_name = base
            else:
                default_name = input_file + ".enc"
        else:
            default_name = "output.enc"
            
        path, _ = QFileDialog.getSaveFileName(self, "Save Output File", default_name)
        if path:
            self.enc_output_edit.setText(path)

    # Hash computation
    @staticmethod
    def compute_file_hash_static(path, algo):
        mapping = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA-256": hashlib.sha256,
            "SHA-512": hashlib.sha512,
            "SHA3-256": hashlib.sha3_256,
            "SHA3-512": hashlib.sha3_512,
        }
        h = mapping.get(algo, hashlib.sha256)()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _compute_file_hash(self, path, algo):
        return MainWindow.compute_file_hash_static(path, algo)

    def _validate_file(self):
        path = self.path_edit.text().strip()
        if not os.path.isfile(path):
            self.status.showMessage("Invalid file")
            return
        digest = self._compute_file_hash(path, self.hash_alg)
        self.result.setText(f"{self.hash_alg}:\n{digest}\n\n{path}")
        self._add_history({
            "type": "file",
            "algorithm": self.hash_alg,
            "input": os.path.abspath(path),
            "hash": digest
        })
        self.status.showMessage("File hash computed successfully")

    # Folder hashing (threaded)
    def _start_folder_hash(self):
        folder = self.folder_edit.text().strip()
        if not os.path.isdir(folder):
            self.status.showMessage("Invalid folder")
            return
        self.stop_flag = False
        self.folder_result.clear()
        self.folder_progress.setValue(0)
        t = threading.Thread(target=self._validate_folder, args=(folder,), daemon=True)
        t.start()
        self._add_history({
            "type": "folder",
            "algorithm": self.hash_alg,
            "input": os.path.abspath(folder),
            "hash": None,
            "note": "started"
        })
        self.status.showMessage("Folder hashing started")

    def _stop_folder_hash(self):
        self.stop_flag = True
        self.status.showMessage("Stopping folder hashing...")

    def _validate_folder(self, folder):
        files = []
        for root, _, filenames in os.walk(folder):
            for fname in filenames:
                files.append(os.path.join(root, fname))
        total = len(files) or 1
        for i, path in enumerate(files, start=1):
            if self.stop_flag:
                break
            try:
                digest = self._compute_file_hash(path, self.hash_alg)
                from PyQt6.QtCore import QTimer
                QTimer.singleShot(0, lambda p=path, d=digest: self.folder_result.append(f"{os.path.relpath(p, folder)}: {d}"))
                QTimer.singleShot(0, lambda v=int((i/total)*100): self.folder_progress.setValue(v))
            except Exception as e:
                from PyQt6.QtCore import QTimer
                QTimer.singleShot(0, lambda p=path, e=e: self.folder_result.append(f"{os.path.relpath(p, folder)}: ERROR ({e})"))
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(0, lambda: self.folder_progress.setValue(100))
        self._add_history({
            "type": "folder",
            "algorithm": self.hash_alg,
            "input": os.path.abspath(folder),
            "hash": f"{len(files)} files",
            "note": "completed" if not self.stop_flag else "stopped"
        })
        self.status.showMessage("Folder hashing finished" if not self.stop_flag else "Folder hashing stopped")

    # Password hashing
    def _hash_password(self):
        pw = self.pass_input.text()
        algo = self.pass_algo.currentText()
        if not pw:
            self.status.showMessage("Enter a password")
            return
        if algo == "Argon2":
            h = PasswordHasher().hash(pw)
        elif algo == "bcrypt":
            h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
        else:
            iterations = 150000
            salt = os.urandom(16)
            dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
            h = f"pbkdf2${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
        self.pass_result.setText(h)
        self._add_history({
            "type": "password",
            "algorithm": algo,
            "input": "<hidden>",
            "hash": h
        })
        self.status.showMessage("Password hashed")

    def _verify_password(self):
        pw = self.verify_input.text()
        hashed = self.pass_result.toPlainText().strip()
        algo = self.pass_algo.currentText()
        if not pw or not hashed:
            self.verify_result.setText("Warning: Please hash a password first.")
            return
        ok = False
        try:
            if hashed.startswith("$argon2") or algo == "Argon2":
                ph = PasswordHasher()
                ok = ph.verify(hashed, pw)
            elif hashed.startswith("$2a$") or hashed.startswith("$2b$") or algo == "bcrypt":
                ok = bcrypt.checkpw(pw.encode(), hashed.encode())
            elif hashed.startswith("pbkdf2$") or algo == "PBKDF2":
                parts = hashed.split("$")
                if len(parts) == 4 and parts[0] == "pbkdf2":
                    iters = int(parts[1])
                    salt = base64.b64decode(parts[2])
                    expected = base64.b64decode(parts[3])
                    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
                    ok = hmac.compare_digest(dk, expected)
                else:
                    ok = False
            else:
                try:
                    ok = PasswordHasher().verify(hashed, pw)
                except Exception:
                    try:
                        ok = bcrypt.checkpw(pw.encode(), hashed.encode())
                    except Exception:
                        ok = False
        except Exception:
            ok = False
        if ok:
            self.verify_result.setText("Password verified.")
            self.verify_result.setStyleSheet(f"color:{PALETTE['success']}")
        else:
            self.verify_result.setText("Verification failed.")
            self.verify_result.setStyleSheet(f"color:{PALETTE['danger']}")
            
    # --- NEW ENCRYPTION LOGIC ---
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 32-byte (AES-256) key from the password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=480000,  # Recommended iteration count
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def _encrypt_file(self, file_path, password, output_path):
        """Encrypts a file using AES-256-GCM."""
        if not os.path.exists(file_path):
            return "Error: Input file not found."

        # 1. Generate Salt and IV
        salt = os.urandom(16)
        iv = os.urandom(12)  # 96-bit IV for GCM

        # 2. Derive Key
        key = self._derive_key(password, salt)

        # 3. Encrypt Data
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        try:
            with open(file_path, "rb") as f_in, open(output_path, "wb") as f_out:
                # Write metadata first (Salt, IV)
                f_out.write(salt)  # 16 bytes
                f_out.write(iv)    # 12 bytes

                # Process file in chunks
                chunk_size = 65536
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    f_out.write(encryptor.update(chunk))

                f_out.write(encryptor.finalize())
                tag = encryptor.tag

                # Write authentication tag last
                f_out.write(tag)  # 16 bytes (for GCM)

            self._add_history({
                "type": "encryption",
                "algorithm": "AES-256-GCM (PBKDF2)",
                "input": os.path.abspath(file_path),
                "hash": os.path.basename(output_path),
                "result": "Success"
            })
            return f"Success: File encrypted to {output_path}"

        except Exception as e:
            if os.path.exists(output_path):
                os.remove(output_path)
            return f"Error during encryption: {e}"

    def _decrypt_file(self, file_path, password, output_path):
        """Decrypts a file encrypted with _encrypt_file."""
        if not os.path.exists(file_path):
            return "Error: Input file not found."

        try:
            with open(file_path, "rb") as f_in:
                # 1. Read metadata (Salt, IV, Tag)
                salt = f_in.read(16)
                iv = f_in.read(12)
                
                # Check file size (must be at least 16 (salt) + 12 (iv) + 16 (tag) = 44 bytes)
                f_in.seek(0, 2)
                file_size = f_in.tell()
                if file_size < 44:
                    return "Error: File too small or corrupted metadata."
                
                f_in.seek(file_size - 16)
                tag = f_in.read(16)
                
                # Go back to the start of ciphertext (after IV)
                f_in.seek(28) 
                
                # 2. Derive Key
                key = self._derive_key(password, salt)

                # 3. Decrypt Data
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()

                with open(output_path, "wb") as f_out:
                    chunk_size = 65536
                    while True:
                        # Read up to the final 16 bytes (tag)
                        ciphertext_chunk = f_in.read(chunk_size)
                        if not ciphertext_chunk or f_in.tell() == file_size - 16:
                            f_out.write(decryptor.update(ciphertext_chunk))
                            break
                        f_out.write(decryptor.update(ciphertext_chunk))

                    f_out.write(decryptor.finalize())

            self._add_history({
                "type": "decryption",
                "algorithm": "AES-256-GCM (PBKDF2)",
                "input": os.path.abspath(file_path),
                "hash": os.path.basename(output_path),
                "result": "Success"
            })
            return f"Success: File decrypted to {output_path}"

        except Exception as e:
            if os.path.exists(output_path):
                os.remove(output_path)
            # This often catches the authentication failure if the password/key is wrong
            return f"Error during decryption/authentication: {e}"

    def _handle_encrypt(self):
        input_path = self.enc_input_edit.text()
        password = self.enc_pass_input.text()
        output_path = self.enc_output_edit.text()
        if not (input_path and password and output_path):
            self.enc_result.setText(f"<span style='color:{PALETTE['danger']}'>Error: All fields are required.</span>")
            self.status.showMessage("Encryption failed: Missing fields.")
            return
        
        self.status.showMessage("Encrypting file... Please wait.")
        result = self._encrypt_file(input_path, password, output_path)
        
        style = PALETTE['success'] if result.startswith("Success") else PALETTE['danger']
        self.enc_result.setText(f"<span style='color:{style}'>{result}</span>")
        self.status.showMessage("Encryption finished.")

    def _handle_decrypt(self):
        input_path = self.enc_input_edit.text()
        password = self.enc_pass_input.text()
        output_path = self.enc_output_edit.text()
        if not (input_path and password and output_path):
            self.enc_result.setText(f"<span style='color:{PALETTE['danger']}'>Error: All fields are required.</span>")
            self.status.showMessage("Decryption failed: Missing fields.")
            return
        
        self.status.showMessage("Decrypting file... Please wait.")
        result = self._decrypt_file(input_path, password, output_path)
        
        style = PALETTE['success'] if result.startswith("Success") else PALETTE['danger']
        self.enc_result.setText(f"<span style='color:{style}'>{result}</span>")
        self.status.showMessage("Decryption finished.")
    # --- END NEW ENCRYPTION LOGIC ---


    # Integrity check
    def _check_integrity(self):
        path = self.check_file_edit.text().strip()
        expected = self.hash_input.text().strip()
        if not os.path.isfile(path):
            self.status.showMessage("Invalid file")
            return
        detected = self._detect_algo(expected)
        actual = self._compute_file_hash(path, detected)
        if hmac.compare_digest(expected.lower(), actual.lower()):
            msg = f"File integrity verified. ({detected})"
            color = PALETTE["success"]
        else:
            msg = f"Integrity mismatch! Actual ({detected}): {actual}"
            color = PALETTE["danger"]
        self.check_output.setStyleSheet(f"color:{color}")
        self.check_output.setText(msg)
        self._add_history({
            "type": "integrity",
            "algorithm": detected,
            "input": os.path.abspath(path),
            "hash": expected,
            "result": msg
        })

    def _detect_algo(self, h):
        h = h.strip()
        if not h:
            return self.hash_alg
        if h.startswith("$argon2"):
            return "Argon2"
        if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
            return "bcrypt"
        if h.startswith("pbkdf2$"):
            return "PBKDF2"
        l = len(h)
        if l == 32: return "MD5"
        if l == 40: return "SHA1"
        if l == 64: return "SHA-256"
        if l == 128: return "SHA-512"
        return self.hash_alg

    # History functions
    def _load_history(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save_history(self):
        try:
            with open(HISTORY_FILE, "w") as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            print("Failed to save history:", e)

    def _add_history(self, record: dict):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "time": now,
            "type": record.get("type", "unknown"),
            "algorithm": record.get("algorithm"),
            "input": record.get("input"),
            "hash": record.get("hash")
        }
        for k, v in record.items():
            if k not in entry:
                entry[k] = v
        self.history.append(entry)
        self.history = self.history[-2000:]
        self._save_history()
        self._refresh_history_ui()

    def _refresh_history_ui(self):
        if hasattr(self, "history_list"):
            self.history_list.clear()
            for item in reversed(self.history[-150:]):
                label = f"[{item['time']}] {item.get('type','?')} - {item.get('algorithm','')} - {os.path.basename(str(item.get('input','')))}"
                q = QListWidgetItem(label)
                q.setToolTip(json.dumps(item, indent=2))
                self.history_list.addItem(q)

    def _clear_history(self):
        confirm = QMessageBox.question(self, "Clear History", "Are you sure you want to clear the history?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            self.history.clear()
            self._save_history()
            self._refresh_history_ui()
            self.status.showMessage("History cleared")

    def _export_history(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export History", filter="JSON Files (*.json)")
        if path:
            try:
                with open(path, "w") as f:
                    json.dump(self.history, f, indent=2)
                self.status.showMessage(f"History exported to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))

    def _import_history(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import History", filter="JSON Files (*.json)")
        if path:
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self.history.extend(data)
                    self._save_history()
                    self._refresh_history_ui()
                    self.status.showMessage(f"Imported {len(data)} history items")
                else:
                    raise ValueError("Invalid history format")
            except Exception as e:
                QMessageBox.critical(self, "Import Failed", str(e))

    def closeEvent(self, event):
        self._save_history()
        event.accept()

# === MAIN ===
if __name__ == "__main__":
    app = QApplication(sys.argv)

    # --- Logo Fix: Set global app icon early ---
    base_dir = pathlib.Path(__file__).resolve().parent
    icon_path = base_dir / "static" / "logo.png"
    if not icon_path.exists():
        # Fallback path for development (adjust this if needed)
        icon_path = pathlib.Path("/home/rixscx/Projects/hash_validator/static/logo.png") 
    if icon_path.exists():
        icon = QIcon(str(icon_path))
        app.setWindowIcon(icon)
    else:
        print(f"[Warning] Icon not found: {icon_path}. Application will use default icon.")

    win = MainWindow()
    if icon_path.exists():
        win.setWindowIcon(QIcon(str(icon_path)))

    win.show()
    sys.exit(app.exec())