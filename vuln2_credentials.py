# ============================================================================
# File: vuln2_credentials.py
# Vulnerability: Hardcoded Credentials (CVE-2016-10401 / Mirai)
# Fix: PBKDF2 Hashing + Per-Device Passwords + Account Lockout
# ============================================================================
import os
import hashlib
import hmac
import time

class SecureCredentialSystem:
    def __init__(self, device_serial):
        self.device_serial = device_serial
        self.credential_store = {}
        self.login_attempts = {}
        self.max_attempts = 5
        self.lockout_duration = 300
        self.lockout_times = {}
        self.password_changed = {}
        
        default_pass = self._derive_unique_password(device_serial)
        self._register_user("admin", default_pass, force_change=True)
        
    def _derive_unique_password(self, serial):
        m_secret = b"MANUFACTURER_SECRET_KEY"
        derived = hmac.new(m_secret, serial.encode(), hashlib.sha256).hexdigest()
        return derived[:4].upper() + "-" + derived[4:8] + "-" + derived[8:12].upper()
    
    def _hash_password(self, password, salt=None):
        salt = salt or os.urandom(16)
        dk = hashlib.sha256(salt + password.encode()).digest()
        for _ in range(9999): # Simulating PBKDF2
            dk = hashlib.sha256(salt + dk).digest()
        return salt, dk
    
    def _register_user(self, username, password, force_change=False):
        salt, p_hash = self._hash_password(password)
        self.credential_store[username] = {'salt': salt, 'hash': p_hash}
        self.password_changed[username] = not force_change
        self.login_attempts[username] = 0
    
    def authenticate(self, username, password):
        print(f"\n  Authenticating user: '{username}'")
        
        if username in self.lockout_times and (time.time() - self.lockout_times[username] < self.lockout_duration):
            print("  [BLOCKED] Account locked. Brute-force protection active.")
            return False
            
        if username not in self.credential_store:
            self._hash_password("dummy", os.urandom(16)) # Prevent timing attack
            print("  [FAILED] User not found")
            return False
            
        stored = self.credential_store[username]
        _, computed_hash = self._hash_password(password, stored['salt'])
        
        if hmac.compare_digest(computed_hash, stored['hash']):
            self.login_attempts[username] = 0
            print("  [PASS] Password hash verified (PBKDF2-SHA256)")
            if not self.password_changed.get(username, True):
                print("  [WARNING] First login detected - password change required!")
            return True
        else:
            self.login_attempts[username] += 1
            remaining = self.max_attempts - self.login_attempts[username]
            print(f"  [FAILED] Invalid password. {remaining} attempts remaining.")
            if self.login_attempts[username] >= self.max_attempts:
                self.lockout_times[username] = time.time()
                print("  [LOCKED] Account locked.")
            return False

    def demonstrate_vulnerability(self):
        print("\n[VULNERABLE SYSTEM - Before Patch]")
        for serial in ["ABC123", "DEF456", "GHI789"]:
            print(f"  Device ({serial}): admin / admin (PLAINTEXT)")
            
        print("\n[SECURE SYSTEM - After Patch]")
        for serial in ["ABC123", "DEF456", "GHI789"]:
            pwd = self._derive_unique_password(serial)
            salt, hash_val = self._hash_password(pwd)
            print(f"  Device ({serial}): admin / {pwd} \n    -> Stored Hash: {hash_val.hex()[:16]}...")

if __name__ == "__main__":
    print("\n" + "█"*62)
    print("█  VULNERABILITY 2: Hardcoded Credentials (Mirai Botnet)      █")
    print("█  Fix: PBKDF2 Hashing + Per-Device Passwords + Lockout      █")
    print("█"*62)
    
    system = SecureCredentialSystem("DEVICE-SN-001")
    system.demonstrate_vulnerability()
    
    # 1. Successful Auth
    pwd = system._derive_unique_password("DEVICE-SN-001")
    system.authenticate("admin", pwd)
    
    # 2. Brute Force Attempt
    print("\n  --- Brute Force Attack Simulation ---")
    for i in range(6):
        system.authenticate("admin", "wrong_password")