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
        
        self.ip_count_map = defaultdict(list)
        self.lock = threading.Lock()
        self._error_count = 0
        
        # FIX: Track packet counts per IP to avoid alerting on single packets
        self.ip_packet_counts = defaultdict(int)  # Track total packets per IP
        self.min_packets_for_alert = 5  # Minimum packets before ML alert (reduces false positives)
        
        self.detector = None      
        self.logic_engine = None  

    def calculate_features(self, packet):
        if not packet.haslayer(IP):
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
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
        
        with self.lock:
            self.ip_count_map[src_ip].append(current_time)
            self.ip_count_map[src_ip] = [t for t in self.ip_count_map[src_ip] if current_time - t <= 2.0]
            count = len(self.ip_count_map[src_ip])
        
        srv_count = count 
        src_bytes = length
        dst_bytes = 0 
        
        ml_features = [src_bytes, dst_bytes, count, srv_count]
        
        display_data = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': packet[IP].proto,
            'length': length,
            'ml_features': ml_features, 
            'anomaly': 'Normal',  # Default: Normal traffic (will be updated by ML if anomaly detected)
            'timestamp': time.strftime("%H:%M:%S", time.localtime())
        }
        return display_data

    def packet_callback(self, packet):
        if self.stop_event.is_set(): return

        try:
            features = self.calculate_features(packet)
            if features:
                # 1. ML CHECK (Hybrid: Anomaly Detection + Attack Classification)
                # FIX: Track packet counts to reduce false positives from single packets
                src_ip = features.get('src_ip')
                if src_ip:
                    with self.lock:
                        self.ip_packet_counts[src_ip] += 1
                        packet_count = self.ip_packet_counts[src_ip]
                
                if self.detector:
                    prediction = self.detector.predict(features)
                    # prediction is now a dict: {'is_anomaly': bool, 'attack_type': str, 'confidence': str}
                    if isinstance(prediction, dict):
                        is_anomaly = prediction.get('is_anomaly', False)
                        attack_type = prediction.get('attack_type', 'Normal')
                        confidence = prediction.get('confidence', 'low')
                        
                        # FIX: Only flag as anomaly if we've seen enough packets from this IP
                        # This prevents false positives from single unusual packets
                        if is_anomaly and packet_count < self.min_packets_for_alert:
                            # Not enough packets yet - downgrade to normal to reduce false positives
                            is_anomaly = False
                            attack_type = 'Normal'
                            confidence = 'low'
                        
                        features['is_anomaly'] = is_anomaly
                        features['attack_type'] = attack_type
                        features['ml_confidence'] = confidence
                        # For backward compatibility, set 'anomaly' field
                        if is_anomaly:
                            features['anomaly'] = attack_type
                        else:
                            features['anomaly'] = 'Normal'
                    else:
                        # Fallback for old format (shouldn't happen with new code)
                        if prediction == -1 and packet_count >= self.min_packets_for_alert:
                            features['anomaly'] = "Anomaly"
                            features['is_anomaly'] = True
                            features['attack_type'] = 'Unknown'
                            features['ml_confidence'] = 'medium'
                        else:
                            features['anomaly'] = "Normal"
                            features['is_anomaly'] = False
                            features['attack_type'] = 'Normal'
                            features['ml_confidence'] = 'low'

                # 2. RULE CHECK
                if self.logic_engine:
                    simple_data = {'src': features['src_ip'], 'dst_port': features['dst_port']}
                    alert_msg = self.logic_engine.check_packet(simple_data)
                    if alert_msg:
                        features['rule_alert'] = alert_msg
                        # Alert will be displayed in GUI, no need for console spam

                self.data_queue.put(features)
        except Exception as e:
            # Log errors but don't spam console
            if hasattr(self, '_error_count'):
                self._error_count += 1
                if self._error_count % 100 == 0:  # Log every 100th error
                    print(f"Error processing packet (count: {self._error_count}): {e}")
            else:
                self._error_count = 1
                print(f"Error processing packet: {e}")

    def run(self):
        # Auto-select best interface
        from scapy.all import conf
        try:
            # Find interface used to reach internet
            best_iface = conf.route.route("8.8.8.8")[0]
            print(f"[Network Engine] Sniffing on interface: {best_iface}")
        except Exception as e:
            print(f"[Network Engine] Could not detect default interface, using default. Error: {e}")
            best_iface = None

        print("[Network Engine] Sniffer started.")
        try:
            if best_iface:
                sniff(iface=best_iface, prn=self.packet_callback, store=0, stop_filter=lambda x: self.stop_event.is_set())
            else:
                sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e:
            print(f"Error: {e}")
            
    def stop(self):
        self.stop_event.set()