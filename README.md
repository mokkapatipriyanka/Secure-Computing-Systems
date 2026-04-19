# 7018SCN Secure Computing Systems - Security Tools Portfolio

Student ID: [Your Student ID]

## Repository Contents

This repository contains three Python-based security tools:

1. secure_auth.py - Secure authentication system
2. siem_lite.py - SIEM threat detection tool
3. malware_scanner.py - Malware analysis and forensics tool

## Requirements

Python 3.10 or higher
Pillow library

Install dependencies:
pip install pillow




## Task 1: Secure Authentication

Run the program:
python secure_auth.py




Features:
- PBKDF2-HMAC-SHA256 hashing with 100,000 iterations
- Unique 16-byte random salt per user using secrets module
- Regex-based password complexity enforcement
- Minimum 12 characters, must contain number and special character
- Brute-force protection via 2-second delay on failed login attempts only
- Secure credential storage in JSON format

Usage:
- Option 1: Register new user (password must meet complexity requirements)
- Option 2: Login (failed attempts trigger time delay)
- Option 3: Exit

## Task 2: SIEM Lite

Run the program:
python siem_lite.py <log_file> <threshold>


Example:
python siem_lite.py auth.log 3


Features:
- Robust log parsing using re.findall() with regex patterns
- Dynamic alert thresholds via sys.argv command-line arguments
- IP address extraction from failed password attempts
- Threat level classification (HIGH for 5+ attempts, MEDIUM for 3-4)
- Structured JSON export for firewall integration
- Comprehensive error handling for missing files and invalid inputs

Parameters:
- log_file: Path to authentication log file
- threshold: Number of failed attempts to trigger alert (positive integer)

Output:
- Console report with all failed login attempts
- threat_report.json containing malicious IP addresses and threat levels

## Task 3: Malware Analysis & Forensics

Run the program:
python malware_scanner.py


Features:
- Safe file hashing using 4096-byte chunks to prevent memory crashes
- SHA-256 signature matching against known malware database
- Physical file quarantine using shutil.move() to isolated vault
- Quarantine logging with timestamps for audit trail
- EXIF metadata extraction from images using Pillow library
- GPS coordinate extraction and Google Maps link generation
- Directory whitelist to protect critical system files
- Recursive directory scanning with os.walk()

Menu Options:
1. Scan single file for malware signatures and EXIF data
2. Scan entire directory recursively
3. Generate SHA-256 hash of file to add to signature database
4. Exit program

Workflow:
1. Use option 3 to generate hash of suspicious file
2. Add hash to MALWARE_SIGNATURES list in code
3. Use option 1 to scan file (will be quarantined if hash matches)
4. Check QUARANTINE_VAULT folder for quarantined files
5. Review quarantine_log.txt for audit trail

## Security Implementations

Task 1:
- PBKDF2-HMAC key derivation function (not basic SHA-256)
- Cryptographically secure random salt generation using secrets module
- Password complexity validation using regular expressions
- Time delays applied only to failed authentication attempts
- Exception handling for user input and file operations

Task 2:
- Regex pattern matching for robust IP extraction
- Command-line argument parsing for operational flexibility
- Type validation and error handling for threshold values
- UTF-8 encoding specification for file reading
- Permission error handling

Task 3:
- Chunked file reading to handle large files safely
- Physical file relocation to isolated quarantine directory
- Comprehensive EXIF tag parsing with error handling
- GPS coordinate conversion to decimal degrees format
- Absolute path comparison for whitelist matching
- Quarantine operation logging for forensic audit trail

## Files Generated

- users.json: Hashed user credentials (Task 1)
- threat_report.json: Malicious IP addresses and threat analysis (Task 2)
- QUARANTINE_VAULT/: Directory containing quarantined malware samples (Task 3)
- QUARANTINE_VAULT/quarantine_log.txt: Audit log of quarantine operations (Task 3)

## Test Data Included

- auth.log: Sample authentication log with failed login attempts
- suspicious_file.txt: Test file for malware scanning demonstration
