import hashlib
import sqlite3
from dotenv import load_dotenv
import logging
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QFileDialog, QMessageBox, 
    QVBoxLayout, QWidget, QLineEdit, QDialog, QLabel, QDialogButtonBox,
    QFormLayout, QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import os
import datetime
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import sys
import platform
import subprocess

# Initialize logging
logging.basicConfig(
    filename="integrity.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("integrity_checker")

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

load_dotenv()

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
    
    # Log and send alert if needed
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
            return -1, -1
    except Exception as e:
        logger.error(f"VirusTotal request failed: {e}")
        return -1, -1

def send_alert(file_path, status):
    """Send email alert for file changes"""
    smtp_server = os.getenv("EMAIL_SERVER")
    smtp_port = int(os.getenv("EMAIL_PORT", 587))
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

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configuration Settings")
        self.setGeometry(200, 200, 400, 300)
        
        layout = QFormLayout()
        
        # VirusTotal API
        self.vtApiEdit = QLineEdit(os.getenv("VT_API_KEY", ""))
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
            "VT_API_KEY": self.vtApiEdit.text(),
            "EMAIL_SERVER": self.emailServerEdit.text(),
            "EMAIL_PORT": self.emailPortEdit.text(),
            "EMAIL_USER": self.emailUserEdit.text(),
            "EMAIL_PASSWORD": self.emailPassEdit.text(),
            "ALERT_RECIPIENT": self.recipientEdit.text()
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
        
        # Add new settings
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



class ScanWorker(QThread):
    progress_updated = pyqtSignal(int, str)  # percent, current file
    scan_finished = pyqtSignal(str) # summary
    error_occurred = pyqtSignal(str) # error message

    def __init__(self, folder):
        super().__init__()
        self.folder = folder
        self._is_running = True

    def run(self):
        conn = connect_db()
        stats = {"Secure": 0, "Modified": 0, "Missing": 0, "New": 0}
        total_files = 0
        processed_files = 0
        
        try:
            # First pass: count files for progress bar
            for root, _, files in os.walk(self.folder):
                if not self._is_running: break
                total_files += len(files)
            
            if total_files == 0:
                self.scan_finished.emit("No files found to scan.")
                conn.close()
                return

            # Second pass: process files
            for root, _, files in os.walk(self.folder):
                if not self._is_running: break
                
                for file in files:
                    if not self._is_running: break
                    
                    file_path = os.path.join(root, file)
                    status, _ = check_integrity(file_path, conn=conn, commit_changes=False)
                    
                    if status in stats:
                        stats[status] += 1
                    
                    processed_files += 1
                    progress_percent = int((processed_files / total_files) * 100)
                    self.progress_updated.emit(progress_percent, f"Scanning: {file}")
            
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

class IntegrityCheckerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        create_table()
        
    def initUI(self):
        self.setWindowTitle("File Integrity Checker")
        self.setGeometry(100, 100, 500, 300)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        self.scanButton = QPushButton("Scan File")
        self.scanButton.clicked.connect(self.scanFile)
        layout.addWidget(self.scanButton)
        
        self.scanFolderButton = QPushButton("Scan Folder")
        self.scanFolderButton.clicked.connect(self.scanFolder)
        layout.addWidget(self.scanFolderButton)
        
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
        self.cancelButton.clicked.connect(self.cancelScan)
        self.cancelButton.setVisible(False)
        self.cancelButton.setStyleSheet("background-color: #ffcccc; color: red;")
        layout.addWidget(self.cancelButton)

        self.cleanupButton = QPushButton("Clear Sensitive Data")
        self.cleanupButton.clicked.connect(self.cleanup_sensitive_data)
        layout.addWidget(self.cleanupButton)
    
    def scanFile(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.process_file(file_path)
    
    def scanFolder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if not folder:
            return

        # UI State for scanning
        self.scanButton.setEnabled(False)
        self.scanFolderButton.setEnabled(False)
        self.settingsButton.setEnabled(False)
        self.cleanupButton.setEnabled(False)
        
        self.progressBar.setVisible(True)
        self.progressBar.setValue(0)
        self.cancelButton.setVisible(True)
        self.statusLabel.setText("Preparing scan...")

        # Setup Thread
        self.worker = ScanWorker(folder)
        self.worker.progress_updated.connect(self.updateProgress)
        self.worker.scan_finished.connect(self.scanFinished)
        self.worker.error_occurred.connect(self.scanError)
        self.worker.start()

    def updateProgress(self, percent, message):
        self.progressBar.setValue(percent)
        self.statusLabel.setText(message)

    def scanFinished(self, summary):
        self.resetUI()
        QMessageBox.information(self, "Scan Result", summary)

    def scanError(self, error_msg):
        self.resetUI()
        QMessageBox.critical(self, "Error", f"An error occurred: {error_msg}")

    def cancelScan(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.stop()
            self.statusLabel.setText("Cancelling...")
            self.worker.wait() # Wait for thread to finish cleanup
            self.resetUI()
            QMessageBox.information(self, "Cancelled", "Scan cancelled by user.")

    def resetUI(self):
        self.scanButton.setEnabled(True)
        self.scanFolderButton.setEnabled(True)
        self.settingsButton.setEnabled(True)
        self.cleanupButton.setEnabled(True)
        
        self.progressBar.setVisible(False)
        self.cancelButton.setVisible(False)
        self.statusLabel.setText("")
    
    def showSettings(self):
        dialog = SettingsDialog(self)
        dialog.exec_()
    
    def showStatus(self):
        log_file = "integrity.log"
        if not os.path.exists(log_file):
            QMessageBox.warning(self, "File Not Found", "Log file does not exist yet.")
            return

        try:
            if platform.system() == "Darwin":  # macOS
                subprocess.call(('open', log_file))
            elif platform.system() == "Windows":  # Windows
                os.startfile(log_file)
            else:  # Linux
                subprocess.call(('xdg-open', log_file))
        except Exception as e:
            msg = QMessageBox()
            msg.setWindowTitle("Scan History")
            msg.setText(f"Could not open log file: {e}\n\nPlease open 'integrity.log' manually.")
            msg.exec_()
    
    def process_file(self, file_path):
        status, hash_value = check_integrity(file_path)
        vt_msg = ""
        
        if status != "Missing" and hash_value:
            try:
                malicious, suspicious = check_virustotal(hash_value)
                if malicious == -1 or suspicious == -1:
                    vt_msg = "\n⚠️ VirusTotal check failed"
                elif malicious > 0 or suspicious > 0:
                    vt_msg = f"\n⚠️ VirusTotal: Malicious={malicious}, Suspicious={suspicious}"
                else:
                    vt_msg = "\n✅ VirusTotal: No threats detected"
            except Exception as e:
                vt_msg = f"\n⚠️ VirusTotal error: {str(e)}"
        
        msg = QMessageBox()
        msg.setWindowTitle("Integrity Check Result")
        
        if status == "Secure":
            msg.setIcon(QMessageBox.Information)
            msg.setText(f"✅ File is secure\n\nPath: {file_path}{vt_msg}")
        elif status == "Modified":
            msg.setIcon(QMessageBox.Warning)
            msg.setText(f"⚠️ File modified!\n\nPath: {file_path}{vt_msg}")
        elif status == "Missing":
            msg.setIcon(QMessageBox.Critical)
            msg.setText(f"❌ File missing\n\nPath: {file_path}{vt_msg}")
        elif status == "New":
            msg.setIcon(QMessageBox.Information)
            msg.setText(f"ℹ️ New file added\n\nPath: {file_path}{vt_msg}")
        
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
    window = IntegrityCheckerGUI()
    window.show()


    # Cleanup
    if os.getenv("AUTO_CLEANUP") == "1":
        clean_env_file()
    
    sys.exit(app.exec_())