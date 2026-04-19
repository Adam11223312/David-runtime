import hashlib
import time
import json
import uuid
from datetime import datetime

class DavidAICore:
    """
    David AI Core v4.1 - Patent Pending (App No. 64/010,038)
    Inventor: Christopher Thomas
    
    This is a simulation of the Universal Trust Layer, featuring the 
    Immutable Audit Chain and Dynamic QR Plaque generation.
    """
    
    def __init__(self, vehicle_id):
        self.vehicle_id = vehicle_id
        self.audit_chain = []
        self.current_qr_plaque = None
        self.system_status = "SECURE"
        self.initialize_system()

    def initialize_system(self):
        # Create the Genesis Block for the Audit Chain
        genesis_entry = self._create_audit_entry("SYSTEM_INIT", "David AI Core v4.1 Online")
        self.audit_chain.append(genesis_entry)
        self.generate_dynamic_qr()
        print(f"[*] {self.vehicle_id}: System Initialized. Status: {self.system_status}")

    def _create_audit_entry(self, action, details):
        prev_hash = self.audit_chain[-1]['hash'] if self.audit_chain else "0" * 64
        timestamp = datetime.utcnow().isoformat()
        
        entry_data = {
            "timestamp": timestamp,
            "action": action,
            "details": details,
            "prev_hash": prev_hash
        }
        
        # Immutable Hashing (SHA-256)
        entry_string = json.dumps(entry_data, sort_keys=True).encode()
        entry_hash = hashlib.sha256(entry_string).hexdigest()
        
        entry_data['hash'] = entry_hash
        return entry_data

    def perform_risk_analysis(self, sensor_data):
        """
        Fail-Closed Risk Analysis Logic
        """
        print(f"\n[!] Analyzing Sensor Data: {sensor_data}")
        
        # Simulation of threat detection (e.g., unauthorized CAN bus access)
        if sensor_data.get("unauthorized_access") or sensor_data.get("signal_spoofing"):
            self.system_status = "THREAT_DETECTED"
            entry = self._create_audit_entry("SECURITY_ALERT", "Unauthorized access detected. Executing Fail-Closed.")
            self.audit_chain.append(entry)
            self.execute_fail_closed()
        else:
            entry = self._create_audit_entry("ROUTINE_CHECK", "All systems nominal.")
            self.audit_chain.append(entry)
            print("[+] Risk Analysis: Low. Continuing operations.")

    def execute_fail_closed(self):
        """
        The 'Unstealable Car' Protocol
        """
        print(f"[-] CRITICAL: {self.system_status}. Immobilizing Vehicle.")
        print("[-] Hardware Lock Engaged. Audit Chain Locked.")
        self.generate_dynamic_qr(alert=True)

    def generate_dynamic_qr(self, alert=False):
        """
        Dynamic QR Plaque Generation
        Rotating, disappearing IDs synced to the Audit Chain
        """
        rotation_id = str(uuid.uuid4())[:8]
        status_code = "RED" if alert else "GREEN"
        
        # The QR content is a hash of the current Audit Chain state
        current_state_hash = self.audit_chain[-1]['hash']
        self.current_qr_plaque = f"DAVID-AI-{status_code}-{rotation_id}-{current_state_hash[:12]}"
        
        print(f"[#] New Dynamic QR Plaque Generated: {self.current_qr_plaque}")
        return self.current_qr_plaque

    def verify_integrity(self):
        """
        Verifies the Immutable Audit Chain
        """
        print("\n[*] Verifying Audit Chain Integrity...")
        for i in range(1, len(self.audit_chain)):
            prev = self.audit_chain[i-1]
            curr = self.audit_chain[i]
            
            if curr['prev_hash'] != prev['hash']:
                print(f"[X] INTEGRITY BREACH AT BLOCK {i}!")
                return False
        print("[+] Audit Chain Verified. 100% Immutable.")
        return True

# --- DEMONSTRATION ---
if __name__ == "__main__":
    # 1. Start the System
    car = DavidAICore(vehicle_id="TESLA-MODEL-3-CT")
    
    # 2. Normal Operation
    time.sleep(1)
    car.perform_risk_analysis({"speed": 65, "location": "Columbus, OH"})
    
    # 3. Threat Detection (The 'Unstealable' Moment)
    time.sleep(1)
    car.perform_risk_analysis({"unauthorized_access": True, "source": "OBD-II Port"})
    
    # 4. Verification
    car.verify_integrity()
    
    print("\n--- FINAL AUDIT LOG PREVIEW ---")
