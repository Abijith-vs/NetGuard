import threading
import queue
import time
import sys
import os

from network_engine import SnifferThread
from gui_dashboard import NetGuardDashboard

# --- UPDATE 1: IMPORT YOUR MODULE ---

try:
    from rule_engine import LogicEngine
    print("[+] Logic Engine loaded successfully.")
except ImportError:
    print("[-] Logic Engine not found. Rules will be disabled.")
    LogicEngine = None

# Validation of ML imports
try:
    from ml_engine import AnomalyDetector
except ImportError:
    print("[-] ML Engine not found")
    AnomalyDetector = None

def main():
    data_queue = queue.Queue()
    
    # Initialize Engines
    print("Initializing Engines...")
    detector = AnomalyDetector() if AnomalyDetector else None
    
    # --- UPDATE 2: INITIALIZE YOUR ENGINE ---
    # Increased thresholds to prevent false positives on normal traffic
    # Adjust these values based on your network's baseline (use diagnose_traffic.py)
    logic_engine = LogicEngine(
        flood_threshold=3000,  # Increased from 1500 (pkts/sec per IP)
        scan_threshold=25,     # Increased from 15 (unique ports)
        window_size=2.0        # Increased from 1.0 (seconds)
    ) if LogicEngine else None
    
    # Initialize Sniffer
    print("Initializing Network Sniffer...")
    sniffer = SnifferThread(data_queue)
    
    # --- UPDATE 3: INJECT YOUR ENGINE INTO SNIFFER ---
    sniffer.detector = detector
    sniffer.logic_engine = logic_engine  # <--- PASSING YOUR CODE TO MEMBER A

    # Define Start/Stop callbacks for GUI
    def start_sniffing():
        if not sniffer.is_alive():
            sniffer.start()
        else:
            sniffer.stop_event.clear()

    def stop_sniffing():
        sniffer.stop()

    class SnifferManager:
        def __init__(self, queue, detector, logic_engine):
            self.queue = queue
            self.detector = detector
            self.logic_engine = logic_engine # Store reference
            self.thread = None
            
        def start(self):
            if self.thread and self.thread.is_alive():
                return
            self.thread = SnifferThread(self.queue)
            self.thread.detector = self.detector
            self.thread.logic_engine = self.logic_engine # Inject here too
            self.thread.start()
            
        def stop(self):
            if self.thread:
                self.thread.stop()
    
    # Updated Manager with Logic Engine
    manager = SnifferManager(data_queue, detector, logic_engine)

    print("Starting GUI...")
    app = NetGuardDashboard(
        start_callback=manager.start,
        stop_callback=manager.stop,
        log_queue=data_queue
    )
    
    app.protocol("WM_DELETE_WINDOW", lambda: (manager.stop(), app.quit()))
    app.mainloop()

if __name__ == "__main__":
    main()