# ============================================================================
# File: vuln3_sensor_data.py
# Vulnerability: Unencrypted Sensor Data (CVE-2019-10964)
# Fix: AES-128-CTR / RC4 + HMAC + Replay Protection
# ============================================================================
import os
import hashlib
import hmac
import struct
import time
import json
from crypto_utils import AES128, RC4

class SecureSensorCommunication:
    def __init__(self, device_id, master_key, mode="AES-CTR"):
        self.device_id = device_id
        self.master_key = master_key
        self.mode = mode
        self.sequence_number = 0
        self.received_sequences = set()
        
        self.session_nonce = os.urandom(8)
        session_key_mat = hashlib.sha256(master_key + self.session_nonce + device_id.encode()).digest()
        
        if mode == "AES-CTR":
            self.aes = AES128(session_key_mat[:16])
            self.nonce = session_key_mat[16:24]
        elif mode == "RC4":
            self.rc4 = RC4(session_key_mat[:16])
            
    def encrypt_sensor_reading(self, sensor_type, value, unit):
        self.sequence_number += 1
        payload = json.dumps({
            'seq': self.sequence_number, 'dev': self.device_id,
            'type': sensor_type, 'val': value, 'unit': unit
        }).encode()
        
        if self.mode == "AES-CTR":
            ctr_nonce = self.nonce[:4] + struct.pack('>I', self.sequence_number)
            encrypted = self.aes.encrypt_ctr(payload, ctr_nonce)
        elif self.mode == "RC4":
            msg_key = hashlib.sha256(self.master_key + struct.pack('>I', self.sequence_number)).digest()[:16]
            encrypted = RC4(msg_key).encrypt(payload)
            
        seq_bytes = struct.pack('>I', self.sequence_number)
        mac = hmac.new(self.master_key, seq_bytes + encrypted, hashlib.sha256).digest()[:16]
        return seq_bytes + encrypted + mac

    def decrypt_sensor_reading(self, packet):
        seq_bytes, encrypted, mac_received = packet[:4], packet[4:-16], packet[-16:]
        seq_num = struct.unpack('>I', seq_bytes)[0]
        
        mac_computed = hmac.new(self.master_key, seq_bytes + encrypted, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(mac_received, mac_computed):
            return None, "MAC failed - data tampered!"
            
        if seq_num in self.received_sequences:
            return None, "Replay attack detected!"
        self.received_sequences.add(seq_num)
        
        if self.mode == "AES-CTR":
            ctr_nonce = self.nonce[:4] + struct.pack('>I', seq_num)
            decrypted = self.aes.decrypt_ctr(encrypted, ctr_nonce)
        elif self.mode == "RC4":
            msg_key = hashlib.sha256(self.master_key + struct.pack('>I', seq_num)).digest()[:16]
            decrypted = RC4(msg_key).decrypt(encrypted)
            
        return json.loads(decrypted.decode()), "OK"

if __name__ == "__main__":
    print("\n" + "█"*62)
    print("█  VULNERABILITY 3: Unencrypted Sensor Data                   █")
    print("█  Fix: AES-128-CTR + HMAC + Replay Protection               █")
    print("█"*62)
    
    sensor_sys = SecureSensorCommunication("MED-PUMP-001", os.urandom(32), mode="AES-CTR")
    
    # 1. Normal Secure Transmission
    packet = sensor_sys.encrypt_sensor_reading("heart_rate", 75, "bpm")
    print(f"\n  Encrypted Packet: {packet.hex()[:40]}...")
    data, status = sensor_sys.decrypt_sensor_reading(packet)
    print(f"  Decrypted: {data} \n  Status: {status}")
    
    # 2. Replay Attack
    print("\n  --- Testing Replay Attack ---")
    data, status = sensor_sys.decrypt_sensor_reading(packet)
    print(f"  Replay Attempt Status: {status}")
    
    # 3. Tampering Attack
    print("\n  --- Testing Tampering ---")
    new_packet = bytearray(sensor_sys.encrypt_sensor_reading("glucose", 110, "mg/dL"))
    new_packet[10] ^= 0xFF
    data, status = sensor_sys.decrypt_sensor_reading(bytes(new_packet))
    print(f"  Tamper Attempt Status: {status}")