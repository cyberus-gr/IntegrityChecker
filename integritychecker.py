import hashlib
import psycopg2
from dotenv import load_dotenv
import logging
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QFileDialog, QMessageBox
import os
import datetime
import requests

load_dotenv() # Load environment variables from .env file

def connect_db():
    return psycopg2.connect(
        dbname=os.getenv("PGDATABASE"),
        user=os.getenv("PGUSER"),
        password=os.getenv("PGPASSWORD"),
        host=os.getenv("PGHOST"),
        port=os.getenv("PGPORT")
    )

# Ensure the database connection is established and the table is created
# before any operations are performed.
def create_table():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('''
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_name = 'file_integrity'
        ) THEN
            CREATE TABLE file_integrity (
                id SERIAL PRIMARY KEY,
                file_path TEXT UNIQUE NOT NULL,
                hash_value TEXT NOT NULL,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT CHECK (status IN ('Secure', 'Modified', 'Missing', 'New'))
            );
        ELSE
            BEGIN
                ALTER TABLE file_integrity DROP CONSTRAINT IF EXISTS file_integrity_status_check;
                ALTER TABLE file_integrity
                ADD CONSTRAINT file_integrity_status_check
                CHECK (status IN ('Secure', 'Modified', 'Missing', 'New'));
            EXCEPTION WHEN duplicate_object THEN
                NULL;
            END;
        END IF;
    END
    $$;
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
    except FileNotFoundError:
        return None

def check_integrity(file_path):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT hash_value FROM file_integrity WHERE file_path = %s", (file_path,))
    result = cur.fetchone()
    
    if result:
        old_hash = result[0]
        new_hash = compute_hash(file_path)
        status = "Secure" if new_hash == old_hash else "Modified"
    else:
        new_hash = compute_hash(file_path)
        status = "Missing" if new_hash is None else "New"
    
    cur.execute("INSERT INTO file_integrity (file_path, hash_value, last_checked, status) VALUES (%s, %s, %s, %s) ON CONFLICT (file_path) DO UPDATE SET hash_value = EXCLUDED.hash_value, last_checked = EXCLUDED.last_checked, status = EXCLUDED.status", (file_path, new_hash, datetime.datetime.now(), status))
    conn.commit()
    cur.close()
    conn.close()
    return status

def check_virustotal(hash_value):
    api_key = os.getenv("VT_API_KEY")
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return malicious, suspicious
    elif response.status_code == 404:
        # File hash not found in VirusTotal
        return 0, 0
    else:
        raise Exception(f"VirusTotal API error: {response.status_code}")

def log_event(event, file_path):
    logging.basicConfig(filename="integrity.log", level=logging.INFO)
    logging.info(f"{datetime.datetime.now()} - {event}: {file_path}")

class IntegrityCheckerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        create_table()
        
    def initUI(self):
        self.setWindowTitle("File Integrity Checker")
        self.setGeometry(100, 100, 500, 300)
        
        self.scanButton = QPushButton("Scan Files", self)
        self.scanButton.setGeometry(50, 50, 150, 40)
        self.scanButton.clicked.connect(self.scanFiles)
    
    def scanFiles(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            status = check_integrity(file_path)
            log_event(status, file_path)

            hash_value = compute_hash(file_path)
            vt_msg = ""
            try:
                malicious, suspicious = check_virustotal(hash_value)
                if malicious > 0 or suspicious > 0:
                    vt_msg = f"\n⚠️ VirusTotal reports:\nMalicious: {malicious}, Suspicious: {suspicious}"
                else:
                    vt_msg = "\n✅ VirusTotal shows no threats."
            except Exception as e:
                vt_msg = f"\n⚠️ VirusTotal check failed: {e}"

            msg = QMessageBox()
            msg.setWindowTitle("Integrity Check Result")

            if status == "Secure":
                msg.setIcon(QMessageBox.Information)
                msg.setText(f"✅ The file is secure.\n\nPath: {file_path}{vt_msg}")
            elif status == "Modified":
                msg.setIcon(QMessageBox.Warning)
                msg.setText(f"⚠️ The file has been modified!\n\nPath: {file_path}{vt_msg}")
            elif status == "Missing":
                msg.setIcon(QMessageBox.Critical)
                msg.setText(f"❌ The file is missing or unreadable.\n\nPath: {file_path}{vt_msg}")
            elif status == "New":
                msg.setIcon(QMessageBox.Information)
                msg.setText(f"ℹ️ This is a new file being added to the database.\n\nPath: {file_path}{vt_msg}")
            else:
                msg.setIcon(QMessageBox.Question)
                msg.setText(f"Unknown status: {status}\n\nPath: {file_path}{vt_msg}")

            msg.exec_()

if __name__ == "__main__":
    app = QApplication([])
    window = IntegrityCheckerGUI()
    window.show()
    app.exec_()
