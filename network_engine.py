import threading
import time
import queue
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

class SnifferThread(threading.Thread):
    def __init__(self, data_queue):
        super().__init__()
        self.data_queue = data_queue
        self.stop_event = threading.Event()
        self.daemon = True
        
        # State for feature calculation
        # ip_timestamps[src_ip] = [list of timestamps]
        self.ip_timestamps = defaultdict(list)
        self.lock = threading.Lock()
        self.detector = None # To be injected by main.py
        self.detector = None 
        self.logic_engine = None

    def calculate_features(self, packet):
        """
        Extracts features from the packet.
        Returns a dictionary or None if packet is not relevant.
        """
        if not packet.haslayer(IP):
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)
        
        src_port = 0
        dst_port = 0
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
        current_time = time.time()
        
        # Calculate 'count' feature: packets from same IP in last 2 seconds
        count = 1
        with self.lock:
            # Clean old timestamps
            self.ip_timestamps[src_ip] = [t for t in self.ip_timestamps[src_ip] if current_time - t <= 2.0]
            self.ip_timestamps[src_ip].append(current_time)
            count = len(self.ip_timestamps[src_ip])
            
        # Simplified feature set for ML model (consistent with NSL-KDD subset we usually pick)
        # Note: In a real system, we'd need more robust feature extraction to match NSL-KDD exactly.
        # Here we map available info to: src_bytes, dst_bytes, count, srv_count (simulated)
        
        # We'll use packet length as a proxy for src_bytes
        src_bytes = length
        dst_bytes = 0 # Can't know response size without tracking flows, set 0 for single packet
        
        srv_count = count # Simplified proxy
        
        features = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'timestamp': current_time,
            'ml_features': [src_bytes, dst_bytes, count, srv_count]
        }
        
        return features

    def packet_callback(self, packet):
        if self.stop_event.is_set():
            return

        try:
            features = self.calculate_features(packet)
            if features:
                # 1. ML CHECK (Existing)
                if self.detector:
                    anomaly_score = self.detector.predict(features)
                    features['anomaly'] = anomaly_score
                
                # 2. RULE CHECK (--- ADD THIS BLOCK ---)
                if self.logic_engine:
                    # We pass a simple dict to your engine
                    # Your engine expects: {'src': IP, 'dst_port': PORT}
                    simple_data = {
                        'src': features['src_ip'],
                        'dst_port': features['dst_port']
                    }
                    alert_msg = self.logic_engine.check_packet(simple_data)
                    
                    if alert_msg:
                        features['rule_alert'] = alert_msg  # Save alert to features
                # -------------------------------------

                self.data_queue.put(features)
        except Exception as e:
            print(f"Error processing packet: {e}")

    def run(self):
        print("Sniffer thread started...")
        # promiscuous=True might require admin privileges on Windows/Linux
        # store=0 avoids keeping packets in memory
        try:
            sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e:
            print(f"Sniffer failed: {e}")
            # Put an error message in queue or handle gracefully?
            # For now just print
            
    def stop(self):
        self.stop_event.set()
