# integritychecker.py
import hashlib
import psycopg2
from dotenv import load_dotenv
import logging
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QFileDialog, QMessageBox, QVBoxLayout, QWidget)
import os
import datetime
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Initialize logging once
logging.basicConfig(
    filename="integrity.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("integrity_checker")

load_dotenv()  # Load environment variables from .env file

def connect_db():
    return psycopg2.connect(
        dbname=os.getenv("PGDATABASE"),
        user=os.getenv("PGUSER"),
        password=os.getenv("PGPASSWORD"),
        host=os.getenv("PGHOST"),
        port=os.getenv("PGPORT")
    )

def create_table():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS file_integrity (
        id SERIAL PRIMARY KEY,
        file_path TEXT UNIQUE NOT NULL,
        hash_value TEXT,
        last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT CHECK (status IN ('Secure', 'Modified', 'Missing', 'New'))
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

def check_integrity(file_path):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT hash_value FROM file_integrity WHERE file_path = %s", (file_path,))
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
            "VALUES (%s, NULL, %s) "
            "ON CONFLICT (file_path) DO UPDATE SET "
            "hash_value = EXCLUDED.hash_value, "
            "last_checked = CURRENT_TIMESTAMP, "
            "status = EXCLUDED.status",
            (file_path, status)
    else:
        cur.execute(
            "INSERT INTO file_integrity (file_path, hash_value, status) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (file_path) DO UPDATE SET "
            "hash_value = EXCLUDED.hash_value, "
            "last_checked = CURRENT_TIMESTAMP, "
            "status = EXCLUDED.status",
            (file_path, new_hash, status))
    
    conn.commit()
    cur.close()
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
            return -1, -1  # Special error code
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
        
        self.statusButton = QPushButton("Check Status")
        self.statusButton.clicked.connect(self.showStatus)
        layout.addWidget(self.statusButton)
    
    def scanFile(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.process_file(file_path)
    
    def scanFolder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            for root, _, files in os.walk(folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.process_file(file_path)
    
    def showStatus(self):
        msg = QMessageBox()
        msg.setWindowTitle("Scan Status")
        msg.setText("Check integrity.log for complete scan history")
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

if __name__ == "__main__":
    app = QApplication([])
    window = IntegrityCheckerGUI()
    window.show()
    app.exec_()