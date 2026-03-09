import hashlib
import sqlite3
import csv
import fnmatch
import platform

__version__ = "1.0.0"
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QFileDialog, QMessageBox,
    QVBoxLayout, QHBoxLayout, QWidget, QLineEdit, QDialog, QLabel,
    QDialogButtonBox, QFormLayout, QProgressBar, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor
import os
import datetime
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import sys

# Initialize logging with rotation (5 MB max, keep 3 backups)
logger = logging.getLogger("integrity_checker")
logger.setLevel(logging.INFO)
_log_handler = RotatingFileHandler(
    "integrity.log", maxBytes=5 * 1024 * 1024, backupCount=3
)
_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(_log_handler)

# Create default .env if doesn't exist
if not os.path.exists('.env'):
    with open('.env', 'w') as f:
        f.write("# Configuration file\n")
        f.write("DB_PATH=file_integrity.db\n")
        f.write("VT_API_KEY=\n")
        f.write("EMAIL_SERVER=\n")
        f.write("EMAIL_PORT=587\n")
        f.write("EMAIL_USER=\n")
        f.write("EMAIL_PASSWORD=\n")
        f.write("ALERT_RECIPIENT=\n")
        f.write("EXCLUDE_PATTERNS=.git,__pycache__,*.pyc,node_modules\n")
        f.write("VT_ENABLED=1\n")
    # Restrict permissions so only the owner can read the file (no effect on Windows)
    os.chmod('.env', 0o600)

load_dotenv()


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def connect_db():
    db_path = os.getenv("DB_PATH", "file_integrity.db")
    return sqlite3.connect(db_path)


def create_table():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS file_integrity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT UNIQUE NOT NULL,
        hash_value TEXT,
        last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT CHECK (status IN ('Secure', 'Modified', 'Missing', 'New'))
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def compute_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Error computing hash for {file_path}: {e}")
        return None


def compute_all_hashes(file_path):
    """Compute MD5, SHA-1, and SHA-256 in a single file read. Returns a dict or None on error."""
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                h_md5.update(chunk)
                h_sha1.update(chunk)
                h_sha256.update(chunk)
        return {
            "md5":    h_md5.hexdigest(),
            "sha1":   h_sha1.hexdigest(),
            "sha256": h_sha256.hexdigest(),
        }
    except Exception as e:
        logger.error(f"Error computing hashes for {file_path}: {e}")
        return None


def _format_size(size_bytes):
    """Return a human-readable file size string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def check_integrity(file_path, conn=None, commit_changes=True):
    should_close = False
    if conn is None:
        conn = connect_db()
        should_close = True

    cur = conn.cursor()
    cur.execute("SELECT hash_value FROM file_integrity WHERE file_path = ?", (file_path,))
    result = cur.fetchone()

    new_hash = compute_hash(file_path)

    if result:
        old_hash = result[0]
        if new_hash:
            status = "Secure" if new_hash == old_hash else "Modified"
        else:
            status = "Missing"
    else:
        status = "Missing" if new_hash is None else "New"

    # Handle NULL hash for missing files
    if status == "Missing":
        cur.execute(
            "INSERT INTO file_integrity (file_path, hash_value, status) "
            "VALUES (?, NULL, ?) "
            "ON CONFLICT (file_path) DO UPDATE SET "
            "hash_value = excluded.hash_value, "
            "last_checked = CURRENT_TIMESTAMP, "
            "status = excluded.status",
            (file_path, status))
    else:
        cur.execute(
            "INSERT INTO file_integrity (file_path, hash_value, status) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT (file_path) DO UPDATE SET "
            "hash_value = excluded.hash_value, "
            "last_checked = CURRENT_TIMESTAMP, "
            "status = excluded.status",
            (file_path, new_hash, status))

    if commit_changes:
        conn.commit()
    cur.close()

    if should_close:
        conn.close()

    logger.info(f"{status}: {file_path}")
    if status in ["Modified", "Missing"]:
        send_alert(file_path, status)

    return status, new_hash


def check_virustotal(hash_value):
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return 0, 0

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0), stats.get("suspicious", 0)
        elif response.status_code == 404:
            return 0, 0
        else:
            logger.error(f"VirusTotal API error: {response.status_code}")
            return None, None
    except Exception as e:
        logger.error(f"VirusTotal request failed: {e}")
        return None, None


def send_alert(file_path, status):
    """Send email alert for file changes"""
    smtp_server = os.getenv("EMAIL_SERVER")
    try:
        smtp_port = int(os.getenv("EMAIL_PORT", 587))
    except ValueError:
        smtp_port = 587
    email_user = os.getenv("EMAIL_USER")
    email_pass = os.getenv("EMAIL_PASSWORD")
    recipient = os.getenv("ALERT_RECIPIENT", email_user)

    if not all([smtp_server, smtp_port, email_user, email_pass]):
        logger.warning("Email alert configuration incomplete")
        return

    subject = f"File Integrity Alert: {status} - {os.path.basename(file_path)}"
    body = (
        f"File Integrity Checker Alert\n\n"
        f"Status: {status}\n"
        f"File Path: {file_path}\n"
        f"Time: {datetime.datetime.now()}"
    )

    msg = MIMEMultipart()
    msg["From"] = email_user
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_user, email_pass)
            server.sendmail(email_user, recipient, msg.as_string())
        logger.info(f"Email alert sent for {file_path}")
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")


def clean_env_file():
    """Securely removes sensitive values from .env file"""
    env_path = '.env'
    if not os.path.exists(env_path):
        return

    sensitive_keys = [
        'VT_API_KEY',
        'EMAIL_PASSWORD',
        'EMAIL_USER',
        'ALERT_RECIPIENT'
    ]

    cleaned_lines = []
    with open(env_path, 'r') as f:
        for line in f:
            # Preserve comments and non-sensitive values
            if any(line.strip().startswith(key + '=') for key in sensitive_keys):
                key = line.split('=', 1)[0].strip()
                line = f"{key}=\n"
            cleaned_lines.append(line)

    with open(env_path, 'w') as f:
        f.writelines(cleaned_lines)

    # Also clear from memory
    for key in sensitive_keys:
        os.environ.pop(key, None)


# ---------------------------------------------------------------------------
# Scan History Dialog — color-coded table, live search, CSV export
# ---------------------------------------------------------------------------

class ScanHistoryDialog(QDialog):
    _STATUS_COLORS = {
        "Secure":   QColor(200, 240, 200),
        "Modified": QColor(255, 235, 155),
        "Missing":  QColor(255, 190, 190),
        "New":      QColor(190, 215, 255),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan History")
        self.setGeometry(150, 150, 900, 520)
        self.setMinimumSize(650, 400)

        layout = QVBoxLayout()

        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Filter:"))
        self.searchEdit = QLineEdit()
        self.searchEdit.setPlaceholderText("Filter by file path or status…")
        self.searchEdit.textChanged.connect(self._filter_table)
        search_layout.addWidget(self.searchEdit)
        layout.addLayout(search_layout)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Status", "File Path", "Hash (SHA-256)", "Last Checked"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(False)
        layout.addWidget(self.table)

        # Summary label
        self.summaryLabel = QLabel("")
        self.summaryLabel.setAlignment(Qt.AlignLeft)
        layout.addWidget(self.summaryLabel)

        # Buttons
        btn_layout = QHBoxLayout()
        export_btn = QPushButton("Export CSV")
        export_btn.clicked.connect(self._export_csv)
        btn_layout.addWidget(export_btn)
        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self._load_data()

    def _load_data(self):
        conn = connect_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT status, file_path, hash_value, last_checked "
            "FROM file_integrity ORDER BY last_checked DESC"
        )
        self._all_rows = cur.fetchall()
        cur.close()
        conn.close()
        # _current_rows tracks what is actually visible (may be filtered)
        self._current_rows = list(self._all_rows)
        self._populate_table(self._current_rows)
        self._update_summary(self._current_rows)

    def _populate_table(self, rows):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for row_idx, (status, file_path, hash_val, last_checked) in enumerate(rows):
            color = self._STATUS_COLORS.get(status, QColor(255, 255, 255))
            short_hash = (hash_val[:16] + "…") if hash_val else "N/A"
            for col, text in enumerate([status or "", file_path or "", short_hash, last_checked or ""]):
                item = QTableWidgetItem(text)
                item.setBackground(color)
                self.table.setItem(row_idx, col, item)
        self.table.resizeColumnToContents(0)
        self.table.resizeColumnToContents(2)
        self.table.resizeColumnToContents(3)
        self.table.setSortingEnabled(True)

    def _update_summary(self, rows):
        counts = {"Secure": 0, "Modified": 0, "Missing": 0, "New": 0}
        for row in rows:
            if row[0] in counts:
                counts[row[0]] += 1
        self.summaryLabel.setText(
            f"Total: {len(rows)}  |  "
            f"Secure: {counts['Secure']}  "
            f"New: {counts['New']}  "
            f"Modified: {counts['Modified']}  "
            f"Missing: {counts['Missing']}"
        )

    def _filter_table(self, text):
        text = text.lower()
        self._current_rows = [
            r for r in self._all_rows
            if text in (r[1] or "").lower() or text in (r[0] or "").lower()
        ]
        self._populate_table(self._current_rows)
        self._update_summary(self._current_rows)

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "scan_results.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Status", "File Path", "Hash (SHA-256)", "Last Checked"])
                # Export the currently visible (possibly filtered) rows
                writer.writerows(self._current_rows)
            QMessageBox.information(self, "Export Complete", f"Results saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Could not export: {e}")


# ---------------------------------------------------------------------------
# Settings Dialog
# ---------------------------------------------------------------------------

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configuration Settings")
        self.setGeometry(200, 200, 420, 380)

        layout = QFormLayout()

        # VirusTotal API
        self.vtEnabledCheck = QCheckBox("Enable VirusTotal scanning")
        self.vtEnabledCheck.setChecked(os.getenv("VT_ENABLED", "1") == "1")
        layout.addRow(self.vtEnabledCheck)

        self.vtApiEdit = QLineEdit(os.getenv("VT_API_KEY", ""))
        self.vtApiEdit.setEchoMode(QLineEdit.Password)
        layout.addRow("VirusTotal API Key:", self.vtApiEdit)

        # Email Settings
        self.emailServerEdit = QLineEdit(os.getenv("EMAIL_SERVER", ""))
        layout.addRow("Email Server:", self.emailServerEdit)

        self.emailPortEdit = QLineEdit(os.getenv("EMAIL_PORT", "587"))
        layout.addRow("Email Port:", self.emailPortEdit)

        self.emailUserEdit = QLineEdit(os.getenv("EMAIL_USER", ""))
        layout.addRow("Email User:", self.emailUserEdit)

        self.emailPassEdit = QLineEdit(os.getenv("EMAIL_PASSWORD", ""))
        self.emailPassEdit.setEchoMode(QLineEdit.Password)
        layout.addRow("Email Password:", self.emailPassEdit)

        self.recipientEdit = QLineEdit(os.getenv("ALERT_RECIPIENT", ""))
        layout.addRow("Alert Recipient:", self.recipientEdit)

        # Exclusion Patterns
        self.excludeEdit = QLineEdit(os.getenv("EXCLUDE_PATTERNS", ""))
        self.excludeEdit.setPlaceholderText(".git, *.pyc, node_modules, __pycache__")
        layout.addRow("Exclude Patterns:", self.excludeEdit)

        # Test Email Button
        self.testEmailButton = QPushButton("Test Email Connection")
        self.testEmailButton.clicked.connect(self.test_email)
        layout.addRow(self.testEmailButton)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel,
            Qt.Horizontal, self
        )
        buttons.accepted.connect(self.save_settings)
        buttons.rejected.connect(self.reject)

        layout.addRow(buttons)
        self.setLayout(layout)

    def test_email(self):
        smtp_server = self.emailServerEdit.text()
        smtp_port = self.emailPortEdit.text()
        email_user = self.emailUserEdit.text()
        email_pass = self.emailPassEdit.text()
        recipient = self.recipientEdit.text()

        if not all([smtp_server, smtp_port, email_user, email_pass, recipient]):
            QMessageBox.warning(self, "Missing Info", "Please fill in all email fields to test.")
            return

        try:
            port = int(smtp_port)
            with smtplib.SMTP(smtp_server, port, timeout=10) as server:
                server.starttls()
                server.login(email_user, email_pass)

                msg = MIMEText("This is a test email from Integrity Checker.")
                msg["Subject"] = "Integrity Checker Test"
                msg["From"] = email_user
                msg["To"] = recipient

                server.sendmail(email_user, recipient, msg.as_string())

            QMessageBox.information(self, "Success", "Test email sent successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Connection Failed", f"Failed to send test email:\n{e}")

    def save_settings(self):
        # Validate port number
        try:
            port = int(self.emailPortEdit.text())
            if not (1 <= port <= 65535):
                raise ValueError("Invalid port number")
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid port number (1-65535)")
            return

        # Validate email format if provided
        if self.recipientEdit.text() and not re.match(r"[^@]+@[^@]+\.[^@]+", self.recipientEdit.text()):
            QMessageBox.warning(self, "Invalid Email", "Please enter a valid email address for the recipient")
            return

        # Update .env file
        env_lines = []
        if os.path.exists('.env'):
            with open('.env', 'r') as f:
                env_lines = f.readlines()

        new_env = []
        settings = {
            "VT_ENABLED": "1" if self.vtEnabledCheck.isChecked() else "0",
            "VT_API_KEY": self.vtApiEdit.text(),
            "EMAIL_SERVER": self.emailServerEdit.text(),
            "EMAIL_PORT": self.emailPortEdit.text(),
            "EMAIL_USER": self.emailUserEdit.text(),
            "EMAIL_PASSWORD": self.emailPassEdit.text(),
            "ALERT_RECIPIENT": self.recipientEdit.text(),
            "EXCLUDE_PATTERNS": self.excludeEdit.text(),
        }

        # Update existing settings
        found_settings = {k: False for k in settings.keys()}
        for line in env_lines:
            if line.strip() and not line.startswith('#'):
                key = line.split('=')[0].strip()
                if key in settings:
                    new_env.append(f"{key}={settings[key]}\n")
                    found_settings[key] = True
                    continue
            new_env.append(line)

        # Add new settings that weren't found
        for key, found in found_settings.items():
            if not found and settings[key]:
                new_env.append(f"{key}={settings[key]}\n")

        # Write back to .env
        with open('.env', 'w') as f:
            f.writelines(new_env)

        # Reload environment
        load_dotenv(override=True)

        QMessageBox.information(self, "Success", "Settings saved successfully!")
        self.accept()


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

class ScanWorker(QThread):
    progress_updated = pyqtSignal(int, str)  # percent, current file
    scan_finished = pyqtSignal(str)           # summary
    error_occurred = pyqtSignal(str)          # error message

    def __init__(self, folder):
        super().__init__()
        self.folder = folder
        self._is_running = True

    def run(self):
        conn = connect_db()
        stats = {"Secure": 0, "Modified": 0, "Missing": 0, "New": 0}
        processed_files = 0

        try:
            # Build exclusion pattern list from settings
            exclude_raw = os.getenv("EXCLUDE_PATTERNS", "")
            exclude_patterns = [p.strip() for p in exclude_raw.split(',') if p.strip()]

            # Single pass: collect file paths, skipping excluded dirs/files
            all_files = []
            for root, dirs, files in os.walk(self.folder):
                if not self._is_running:
                    break
                # Prune excluded directories in-place so os.walk won't descend into them
                if exclude_patterns:
                    dirs[:] = [
                        d for d in dirs
                        if not any(fnmatch.fnmatch(d, pat) for pat in exclude_patterns)
                    ]
                for file in files:
                    if exclude_patterns and any(fnmatch.fnmatch(file, pat) for pat in exclude_patterns):
                        continue
                    all_files.append(os.path.join(root, file))

            total_files = len(all_files)
            if total_files == 0:
                self.scan_finished.emit("No files found to scan.")
                conn.close()
                return

            # Process collected files
            for file_path in all_files:
                if not self._is_running:
                    break

                status, _ = check_integrity(file_path, conn=conn, commit_changes=False)

                if status in stats:
                    stats[status] += 1

                processed_files += 1
                progress_percent = int((processed_files / total_files) * 100)
                self.progress_updated.emit(progress_percent, f"Scanning: {os.path.basename(file_path)}")

            if self._is_running:
                conn.commit()
                summary = (
                    f"Scanned {total_files} files.\n\n"
                    f"✅ Secure: {stats['Secure']}\n"
                    f"ℹ️ New: {stats['New']}\n"
                    f"⚠️ Modified: {stats['Modified']}\n"
                    f"❌ Missing: {stats['Missing']}"
                )
                self.scan_finished.emit(summary)
            else:
                self.scan_finished.emit("Scan cancelled.")

        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.error_occurred.emit(str(e))
        finally:
            conn.close()

    def stop(self):
        self._is_running = False


# ---------------------------------------------------------------------------
# About dialog
# ---------------------------------------------------------------------------

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About File Integrity Checker")
        self.setFixedSize(360, 210)

        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel("File Integrity Checker")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #89b4fa;")
        layout.addWidget(title)

        version_label = QLabel(f"Version {__version__}")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)

        desc = QLabel(
            "Cross-platform file integrity monitoring.\n"
            "SHA-256 · SHA-1 · MD5 hashing  |  VirusTotal integration\n"
            "Email alerts  |  Baseline locking  |  CSV export"
        )
        desc.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc)

        link = QLabel(
            '<a href="https://github.com/mmcyberus/IntegrityChecker" '
            'style="color:#89b4fa;">github.com/mmcyberus/IntegrityChecker</a>'
            "  ·  MIT License"
        )
        link.setAlignment(Qt.AlignCenter)
        link.setOpenExternalLinks(True)
        link.setStyleSheet("font-size: 11px; color: #585b70;")
        layout.addWidget(link)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

        self.setLayout(layout)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

def _build_stylesheet():
    """Return the QSS stylesheet using the correct system font for this platform."""
    _sys = platform.system()
    if _sys == "Windows":
        font = '"Segoe UI", Arial'
    elif _sys == "Darwin":
        font = '"Helvetica Neue", Arial'
    else:
        font = '"Ubuntu", "DejaVu Sans", Arial'

    return f"""
QMainWindow, QDialog {{
    background-color: #1e1e2e;
}}
QWidget {{
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: {font};
    font-size: 13px;
}}
QPushButton {{
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 7px 14px;
    min-height: 28px;
}}
QPushButton:hover {{
    background-color: #45475a;
    border-color: #89b4fa;
}}
QPushButton:pressed {{
    background-color: #89b4fa;
    color: #1e1e2e;
}}
QPushButton:disabled {{
    background-color: #181825;
    color: #585b70;
    border-color: #313244;
}}
QPushButton#cancelButton {{
    background-color: #3b1f1f;
    color: #f38ba8;
    border-color: #f38ba8;
}}
QPushButton#cancelButton:hover {{
    background-color: #f38ba8;
    color: #1e1e2e;
}}
QLineEdit, QTextEdit, QPlainTextEdit {{
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 4px 8px;
}}
QLineEdit:focus {{
    border-color: #89b4fa;
}}
QProgressBar {{
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 4px;
    text-align: center;
    color: #cdd6f4;
}}
QProgressBar::chunk {{
    background-color: #89b4fa;
    border-radius: 3px;
}}
QLabel {{
    color: #cdd6f4;
}}
QTableWidget {{
    background-color: #181825;
    gridline-color: #313244;
    border: 1px solid #45475a;
}}
QTableWidget::item:selected {{
    background-color: #45475a;
}}
QHeaderView::section {{
    background-color: #313244;
    color: #89b4fa;
    border: none;
    padding: 5px;
    font-weight: bold;
}}
QScrollBar:vertical {{
    background: #181825;
    width: 10px;
}}
QScrollBar::handle:vertical {{
    background: #45475a;
    border-radius: 5px;
    min-height: 20px;
}}
QMessageBox {{
    background-color: #1e1e2e;
}}
"""


class IntegrityCheckerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        create_table()

    def initUI(self):
        self.setWindowTitle("File Integrity Checker")
        self.setGeometry(100, 100, 460, 380)
        self.setMinimumWidth(380)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)
        central_widget.setLayout(layout)

        self.scanButton = QPushButton("Scan File")
        self.scanButton.clicked.connect(self.scanFile)
        layout.addWidget(self.scanButton)

        self.scanFolderButton = QPushButton("Scan Folder")
        self.scanFolderButton.clicked.connect(self.scanFolder)
        layout.addWidget(self.scanFolderButton)

        self.lockBaselineButton = QPushButton("Lock Baseline")
        self.lockBaselineButton.clicked.connect(self.lockBaseline)
        layout.addWidget(self.lockBaselineButton)

        self.settingsButton = QPushButton("Configure Settings")
        self.settingsButton.clicked.connect(self.showSettings)
        layout.addWidget(self.settingsButton)

        self.statusButton = QPushButton("View Scan History")
        self.statusButton.clicked.connect(self.showStatus)
        layout.addWidget(self.statusButton)

        self.progressBar = QProgressBar()
        self.progressBar.setValue(0)
        self.progressBar.setVisible(False)
        layout.addWidget(self.progressBar)

        self.statusLabel = QLabel("")
        self.statusLabel.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.statusLabel)

        self.cancelButton = QPushButton("Cancel Scan")
        self.cancelButton.setObjectName("cancelButton")
        self.cancelButton.clicked.connect(self.cancelScan)
        self.cancelButton.setVisible(False)
        layout.addWidget(self.cancelButton)

        self.cleanupButton = QPushButton("Clear Sensitive Data")
        self.cleanupButton.clicked.connect(self.cleanup_sensitive_data)
        layout.addWidget(self.cleanupButton)

        self.aboutButton = QPushButton("About")
        self.aboutButton.clicked.connect(self.showAbout)
        layout.addWidget(self.aboutButton)

    def scanFile(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.process_file(file_path)

    def scanFolder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if not folder:
            return

        self._set_scanning_ui(True)
        self.statusLabel.setText("Preparing scan…")

        self.worker = ScanWorker(folder)
        self.worker.progress_updated.connect(self.updateProgress)
        self.worker.scan_finished.connect(self.scanFinished)
        self.worker.error_occurred.connect(self.scanError)
        self.worker.start()

    def _set_scanning_ui(self, scanning: bool):
        for btn in [self.scanButton, self.scanFolderButton, self.lockBaselineButton,
                    self.settingsButton, self.statusButton, self.cleanupButton, self.aboutButton]:
            btn.setEnabled(not scanning)
        self.progressBar.setVisible(scanning)
        self.cancelButton.setVisible(scanning)
        if scanning:
            self.progressBar.setValue(0)

    def updateProgress(self, percent, message):
        self.progressBar.setValue(percent)
        self.statusLabel.setText(message)

    def scanFinished(self, summary):
        self._set_scanning_ui(False)
        self.statusLabel.setText("")
        QMessageBox.information(self, "Scan Result", summary)

    def scanError(self, error_msg):
        self._set_scanning_ui(False)
        self.statusLabel.setText("")
        QMessageBox.critical(self, "Error", f"An error occurred: {error_msg}")

    def cancelScan(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.stop()
            self.statusLabel.setText("Cancelling…")
            if not self.worker.wait(3000):  # 3 s timeout to avoid freezing the UI
                self.worker.terminate()
            self._set_scanning_ui(False)
            self.statusLabel.setText("")
            QMessageBox.information(self, "Cancelled", "Scan cancelled by user.")

    def showAbout(self):
        AboutDialog(self).exec_()

    def showSettings(self):
        dialog = SettingsDialog(self)
        dialog.exec_()

    def showStatus(self):
        dialog = ScanHistoryDialog(self)
        dialog.exec_()

    def lockBaseline(self):
        """Accept the current state of Modified files as the new trusted baseline."""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Lock Baseline")
        if not folder:
            return

        confirm = QMessageBox.question(
            self,
            "Lock Baseline",
            f"Accept the current state of all Modified files in:\n{folder}\n\n"
            "Their current hash will become the new trusted baseline "
            "and they will be marked Secure.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return

        conn = connect_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT file_path FROM file_integrity "
            "WHERE status = 'Modified' AND file_path LIKE ?",
            (folder + "%",)
        )
        modified = cur.fetchall()
        updated = 0
        for (fp,) in modified:
            new_hash = compute_hash(fp)
            if new_hash:
                cur.execute(
                    "UPDATE file_integrity SET hash_value = ?, status = 'Secure', "
                    "last_checked = CURRENT_TIMESTAMP WHERE file_path = ?",
                    (new_hash, fp)
                )
                updated += 1
        conn.commit()
        cur.close()
        conn.close()

        logger.info(f"Baseline locked for {updated} file(s) in {folder}")
        QMessageBox.information(
            self, "Baseline Locked",
            f"Baseline locked for {updated} modified file(s).\nThey are now marked Secure."
        )

    def process_file(self, file_path):
        status, hash_value = check_integrity(file_path)
        extra = ""

        vt_enabled = os.getenv("VT_ENABLED", "1") == "1"
        vt_key = os.getenv("VT_API_KEY", "")

        if status != "Missing" and hash_value:
            if vt_enabled and vt_key:
                # --- VirusTotal path ---
                try:
                    malicious, suspicious = check_virustotal(hash_value)
                    if malicious is None or suspicious is None:
                        extra = "\n⚠️ VirusTotal check failed"
                    elif malicious > 0 or suspicious > 0:
                        extra = f"\n⚠️ VirusTotal: Malicious={malicious}, Suspicious={suspicious}"
                    else:
                        extra = "\n✅ VirusTotal: No threats detected"
                except Exception as e:
                    extra = f"\n⚠️ VirusTotal error: {e}"
            else:
                # --- Local-only path: compute all three hashes and file metadata ---
                hashes = compute_all_hashes(file_path)
                try:
                    stat = os.stat(file_path)
                    size_str = _format_size(stat.st_size)
                    mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                except OSError:
                    size_str = "unknown"
                    mtime = "unknown"

                if hashes:
                    extra = (
                        f"\n\n── Local Hash Analysis ──"
                        f"\n  SHA-256 : {hashes['sha256']}"
                        f"\n  SHA-1   : {hashes['sha1']}"
                        f"\n  MD5     : {hashes['md5']}"
                        f"\n\n── File Metadata ──"
                        f"\n  Size    : {size_str}"
                        f"\n  Modified: {mtime}"
                    )
                if not vt_enabled:
                    extra += "\n\n[VirusTotal disabled in settings]"
                elif not vt_key:
                    extra += "\n\n[VirusTotal API key not configured]"

        msg = QMessageBox()
        msg.setWindowTitle("Integrity Check Result")

        if status == "Secure":
            msg.setIcon(QMessageBox.Information)
            msg.setText(f"✅ File is secure\n\nPath: {file_path}{extra}")
        elif status == "Modified":
            msg.setIcon(QMessageBox.Warning)
            msg.setText(f"⚠️ File modified!\n\nPath: {file_path}{extra}")
        elif status == "Missing":
            msg.setIcon(QMessageBox.Critical)
            msg.setText(f"❌ File missing\n\nPath: {file_path}")
        elif status == "New":
            msg.setIcon(QMessageBox.Information)
            msg.setText(f"ℹ️ New file added\n\nPath: {file_path}{extra}")

        msg.exec_()

    def cleanup_sensitive_data(self):
        confirm = QMessageBox.question(
            self,
            "Confirm Cleanup",
            "This will remove all API keys and credentials from .env!\nContinue?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            clean_env_file()
            QMessageBox.information(
                self,
                "Cleanup Complete",
                "Sensitive data removed from .env file"
            )


if __name__ == "__main__":
    app = QApplication([])
    app.setStyleSheet(_build_stylesheet())
    window = IntegrityCheckerGUI()
    window.show()

    # Cleanup
    if os.getenv("AUTO_CLEANUP") == "1":
        clean_env_file()

    sys.exit(app.exec_())
