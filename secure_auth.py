import hashlib
import os
import re
import time
import json
import secrets

USERS_FILE = "users.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def validate_password_complexity(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&* etc.)"
    
    return True, "Password is strong"

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    
    return hashed.hex(), salt

def register_user(username, password):
    users = load_users()
    
    if username in users:
        print(f"[ERROR] User '{username}' already exists!")
        return False
    
    is_valid, message = validate_password_complexity(password)
    if not is_valid:
        print(f"[ERROR] {message}")
        return False
    
    hashed_password, salt = hash_password(password)
    
    users[username] = {
        'password_hash': hashed_password,
        'salt': salt.hex()
    }
    
    save_users(users)
    print(f"[SUCCESS] User '{username}' registered successfully!")
    print(f"[INFO] Password complexity: Length Number Special character")
    return True

def login_user(username, password):
    users = load_users()
    
    if username not in users:
        print(f"[FAILED] Invalid username or password")
        time.sleep(2)
        return False
    
    stored_hash = users[username]['password_hash']
    salt = bytes.fromhex(users[username]['salt'])
    
    attempted_hash, _ = hash_password(password, salt)
    
    if attempted_hash == stored_hash:
        print(f"[SUCCESS] Welcome, {username}!")
        return True
    else:
        print(f"[FAILED] Invalid username or password")
        print("[SECURITY] Brute-force protection: 2-second delay activated")
        time.sleep(2)
        return False

def main():
    print("=" * 60)
    print("SECURE AUTHENTICATION SYSTEM")
    print("=" * 60)
    
    while True:
        print("\n[MENU]")
        print("1. Register new user")
        print("2. Login")
        print("3. Exit")
        
        try:
            choice = input("\nEnter choice (1-3): ").strip()
            
            if choice == '1':
                print("\n--- REGISTRATION ---")
                username = input("Enter username: ").strip()
                
                if not username:
                    print("[ERROR] Username cannot be empty!")
                    continue
                    
                password = input("Enter password: ").strip()
                
                print("\n[PASSWORD REQUIREMENTS]")
                print("Minimum 12 characters")
                print("At least one number (0-9)")
                print("At least one special character (!@#$%^&* etc.)")
                print()
                
                register_user(username, password)
                
            elif choice == '2':
                print("\n--- LOGIN ---")
                username = input("Enter username: ").strip()
                password = input("Enter password: ").strip()
                
                login_user(username, password)
                
            elif choice == '3':
                print("\n[EXIT] Goodbye!")
                break
            else:
                print("[ERROR] Invalid choice. Please enter 1, 2, or 3.")
                
        except KeyboardInterrupt:
            print("\n\n[EXIT] Program interrupted by user.")
            break
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")

if __name__ == "__main__":
    main()