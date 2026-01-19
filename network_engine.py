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
        
        # --- Memory for Features ---
        self.ip_count_map = defaultdict(list)
        self.lock = threading.Lock()
        
        # --- Engine Injection ---
        self.detector = None      # Will hold your ML Engine
        self.logic_engine = None  # Will hold your Rule Engine

    def calculate_features(self, packet):
        """
        Extracts features for the ML model.
        """
        if not packet.haslayer(IP):
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        
        # Get Ports
        src_port = 0
        dst_port = 0
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
        current_time = time.time()
        
        # --- UPDATE COUNTERS ---
        with self.lock:
            self.ip_count_map[src_ip].append(current_time)
            # Keep only last 2 seconds
            self.ip_count_map[src_ip] = [t for t in self.ip_count_map[src_ip] if current_time - t <= 2.0]
            count = len(self.ip_count_map[src_ip])
        
        srv_count = count 
        src_bytes = length
        dst_bytes = 0 
        
        # PREPARE DATA
        ml_features = [src_bytes, dst_bytes, count, srv_count]
        
        display_data = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': packet[IP].proto,
            'length': length,
            'ml_features': ml_features, 
            'anomaly': "Normal", # Default
            'timestamp': time.strftime("%H:%M:%S", time.localtime())
        }
        
        return display_data

    def packet_callback(self, packet):
        if self.stop_event.is_set():
            return

        try:
            features = self.calculate_features(packet)
            if features:
                
                # --- 1. ML CHECK (The "Mechanic") ---
                if self.detector:
                    # prediction will be a String (e.g., "DoS") or Number (-1/1)
                    prediction = self.detector.predict(features)
                    features['anomaly'] = prediction
                    
                    # --- TERMINAL LOGGING LOGIC ---
                    is_attack = False
                    attack_name = "Anomaly"

                    # Check for String Prediction (New Model)
                    if isinstance(prediction, str) and prediction != "Normal":
                        is_attack = True
                        attack_name = prediction
                    
                    # Check for Number Prediction (Old Model Fallback)
                    elif prediction == -1:
                        is_attack = True
                    
                    if is_attack:
                        # PRINT RED ALERT TO TERMINAL
                        # \033[91m = Red Color, \033[0m = Reset Color
                        print(f"\033[91m⚠️  [ML ALERT] {attack_name} Detected! Source: {features['src_ip']}\033[0m")
                    else:
                        # Optional: Print simple dot for normal traffic so you know it's working
                        # print(".", end="", flush=True) 
                        pass

                # --- 2. RULE CHECK (The "Rule Book") ---
                if self.logic_engine:
                    simple_data = {'src': features['src_ip'], 'dst_port': features['dst_port']}
                    alert_msg = self.logic_engine.check_packet(simple_data)
                    if alert_msg:
                        features['rule_alert'] = alert_msg
                        print(f"\033[93m⚠️  [RULE ALERT] {alert_msg}\033[0m") # Yellow Text

                # Send to GUI
                self.data_queue.put(features)
                
        except Exception as e:
            pass

    def run(self):
        print("[Network Engine] Sniffer started. Waiting for packets...")
        try:
            sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e:
            print(f"[Network Engine] Error: {e}")
            
    def stop(self):
        self.stop_event.set()