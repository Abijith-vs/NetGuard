import threading
import queue
import time
import sys
import os

from network_engine import SnifferThread
from gui_dashboard import NetGuardDashboard
# Validation of imports
try:
    from ml_engine import AnomalyDetector
except ImportError:
    print("ML Engine not found")
    AnomalyDetector = None

def main():
    # Initialize Queues
    # data_queue will hold dictionary: {'src_ip':..., 'ml_features':..., 'anomaly': -1/1}
    data_queue = queue.Queue()
    
    # Initialize ML Engine
    print("Initializing ML Engine...")
    detector = AnomalyDetector() if AnomalyDetector else None
    
    # We need to bridge the Sniffer and the GUI/Queue.
    # The Sniffer produces raw feature dicts.
    # We want to add the 'anomaly' prediction before it hits the GUI queue.
    # Since we can't easily change SnifferThread instance logic without modifying the file,
    # we'll modify it to accept the detector or we do it here?
    # 
    # Actually, the best way given the constraints and the previous files 
    # is to modify network_engine.py or subclass it. 
    # But I will assume I updating network_engine.py next.
    
    # Initialize Sniffer
    # We will update SnifferThread to take the detector.
    print("Initializing Network Sniffer...")
    sniffer = SnifferThread(data_queue)
    
    # Inject detector into sniffer (Monkey patch or property if not in __init__)
    # I will add a property 'model' to sniffer in the next step.
    sniffer.detector = detector 

    # Define Start/Stop callbacks for GUI
    def start_sniffing():
        if not sniffer.is_alive():
            sniffer.start()
        else:
            # If already started but stopped via event, clear event
            sniffer.stop_event.clear()
            # If thread dead, re-instantiate? Thread usually can only start once.
            # SnifferThread logic in network_engine needs to support restart or be re-created.
            # The current implementation inherits Thread, so it can only run once.
            # We need to re-create it if it finished.
            pass

    def stop_sniffing():
        sniffer.stop()

    # NOTE: Thread restart ability limitation. 
    # If the user stops and starts, we need a new thread.
    # So we need a wrapper class or manage it in the callbacks.
    
    class SnifferManager:
        def __init__(self, queue, detector):
            self.queue = queue
            self.detector = detector
            self.thread = None
            
        def start(self):
            if self.thread and self.thread.is_alive():
                return
            self.thread = SnifferThread(self.queue)
            self.thread.detector = self.detector # Inject detector
            self.thread.start()
            
        def stop(self):
            if self.thread:
                self.thread.stop()
    
    manager = SnifferManager(data_queue, detector)

    # Initialize GUI
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
