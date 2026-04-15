# ============================================================================
# File: vuln1_firmware_ota.py
# Vulnerability: Plaintext Firmware OTA (CVE-2019-12271)
# Fix: AES-128-CBC + HMAC-SHA256
# ============================================================================
import os
import hashlib
import hmac
import struct
from crypto_utils import AES128

class SecureFirmwareOTA:
    def __init__(self, master_key):
        self.master_key = master_key
        self.enc_key = hashlib.sha256(master_key + b"ENCRYPTION").digest()[:16]
        self.mac_key = hashlib.sha256(master_key + b"AUTHENTICATION").digest()
        self.aes = AES128(self.enc_key)
        self.current_version = 0
        
    def _pad_pkcs7(self, data, block_size=16):
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)
    
    def _unpad_pkcs7(self, data):
        pad_len = data[-1]
        return data[:-pad_len]
    
    def _aes_cbc_encrypt(self, plaintext, iv):
        padded = self._pad_pkcs7(plaintext)
        ciphertext, prev_block = bytearray(), iv
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            xored = bytes([b ^ p for b, p in zip(block, prev_block)])
            encrypted = self.aes.encrypt_block(xored)
            ciphertext.extend(encrypted)
            prev_block = encrypted
        return bytes(ciphertext)
    
    def _aes_cbc_decrypt(self, ciphertext, iv):
        plaintext, prev_block = bytearray(), iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted = self.aes.decrypt_block(block)
            plain_block = bytes([d ^ p for d, p in zip(decrypted, prev_block)])
            plaintext.extend(plain_block)
            prev_block = block
        return self._unpad_pkcs7(bytes(plaintext))
    
    def package_firmware(self, firmware_data, version):
        print(f"\n{'='*60}\nSECURE FIRMWARE PACKAGING (Server Side)\n{'='*60}")
        iv = os.urandom(16)
        encrypted_firmware = self._aes_cbc_encrypt(firmware_data, iv)
        package_body = struct.pack('>I', version) + iv + encrypted_firmware
        mac = hmac.new(self.mac_key, package_body, hashlib.sha256).digest()
        complete_package = package_body + mac
        
        print(f"  Firmware size:        {len(firmware_data)} bytes")
        print(f"  Firmware version:     {version}")
        print(f"  IV (hex):             {iv.hex()[:32]}...")
        print(f"  Encrypted size:       {len(encrypted_firmware)} bytes")
        print(f"  HMAC-SHA256:          {mac.hex()[:32]}...")
        print(f"  Total package size:   {len(complete_package)} bytes")
        return complete_package
    
    def verify_and_install(self, package):
        print(f"\n{'='*60}\nSECURE FIRMWARE VERIFICATION (Device Side)\n{'='*60}")
        received_mac, package_body = package[-32:], package[:-32]
        computed_mac = hmac.new(self.mac_key, package_body, hashlib.sha256).digest()
        
        if not hmac.compare_digest(received_mac, computed_mac):
            print("  [FAILED] HMAC verification failed - firmware TAMPERED!")
            return False, None
        print("  [PASS] HMAC-SHA256 integrity check PASSED")
        
        version = struct.unpack('>I', package_body[:4])[0]
        if version <= self.current_version:
            print(f"  [FAILED] Rollback attack detected! Current: {self.current_version}, Received: {version}")
            return False, None
        
        iv, encrypted_firmware = package_body[4:20], package_body[20:]
        decrypted_firmware = self._aes_cbc_decrypt(encrypted_firmware, iv)
        
        self.current_version = version
        print(f"  [SUCCESS] Firmware v{version} verified and installed!")
        return True, decrypted_firmware

if __name__ == "__main__":
    print("\n" + "█"*62)
    print("█  VULNERABILITY 1: Plaintext Firmware Updates                 █")
    print("█  Fix: AES-128-CBC + HMAC-SHA256                            █")
    print("█"*62)
    
    master_key = b"SecureOTAKey!2024"
    server, device = SecureFirmwareOTA(master_key), SecureFirmwareOTA(master_key)
    
    # 1. Normal Update
    firmware_v2 = b"FIRMWARE_BINARY_v2.0_" + os.urandom(100)
    pkg = server.package_firmware(firmware_v2, version=2)
    device.verify_and_install(pkg)
    
    # 2. Tampered Update Attempt
    print("\n  --- Testing Tampered Firmware ---")
    tampered = bytearray(pkg)
    tampered[30] ^= 0xFF
    device.verify_and_install(bytes(tampered))
    
    # 3. Rollback Attack Attempt
    print("\n  --- Testing Rollback Attack ---")
    old_pkg = server.package_firmware(b"OLD_FIRMWARE", version=1)
    device.verify_and_install(old_pkg)