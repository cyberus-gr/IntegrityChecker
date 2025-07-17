# File Integrity Checker

A user-friendly,GUI-based file integrity monitor with sql storage, email alerts, and VirusTotal integration.

## Features
✅ File hash verification (SHA-256)  
✅ Automatic SQLite database setup    
📧 Email alerts on file changes  
🖥️ PyQt5 GUI interface  
🔍 VirusTotal threat detection  
📁 Folder scanning capability 

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/IntegrityChecker.git
   cd IntegrityChecker

## Install Dependencies
pip install -r requirements.txt

## Run the application 
python IntegrityChecker.py


# Creating an Executable (.exe)
pyinstaller --onefile --windowed integrity_checker.py

---

## **📌 4. Add a `.gitignore`**
This prevents unnecessary files from being committed:


## Windows Users - Creating an EXE
pyinstaller --onefile --windowed integrity_checker.py


###
```md
# How to Use File Integrity Checker

1️⃣ **Select a Folder** - Click "Select Folder" to choose a directory.  
2️⃣ **Scan Files** - Click "Scan & Store Hashes" to save file hashes.  
3️⃣ **Verify Integrity** - Click "Check Integrity" to detect changes.  
4️⃣ **Get Alerts** - If a file changes, you will receive an email alert.  

---

## **📌 5. Push to GitHub**
1. **Initialize Git:**
   ```sh
   git init
   git add .
   git commit -m "Initial commit"


## Push to GitHub
git branch -M main
git remote add origin https://github.com/yourusername/IntegrityChecker.git
git push -u origin main
