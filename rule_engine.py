# File: rule_engine/rule_engine.py
# Author: Member B

import time
from collections import defaultdict

class LogicEngine:
    def __init__(self):
        # --- CONFIGURATION (Adjust these if alerts are too sensitive) ---
        self.FLOOD_THRESHOLD = 100  # Max packets allowed per second from one IP
        self.SCAN_THRESHOLD = 15    # Max unique ports touched per second by one IP
        
        # --- MEMORY ---
        # 1. Track how many packets each IP sent: {'192.168.1.5': 50}
        self.ip_traffic = defaultdict(int)
        
        # 2. Track which ports an IP has hit: {'192.168.1.5': {80, 443, 21}}
        self.port_scan_map = defaultdict(set)
        
        # 3. Time tracking to reset counters
        self.start_time = time.time()

    def check_packet(self, packet_data):
        """
        Analyzes a single packet for anomalies.
        Input: packet_data (dict) -> {'src': '...', 'dst_port': 80, ...}
        Output: Alert String (if anomaly) or None
        """
        
        # 1. TIME WINDOW CHECK
        # Every 1 second, we wipe the memory. 
        # Without this, every user would eventually get banned just for using the internet.
        current_time = time.time()
        if current_time - self.start_time > 1.0:
            self.reset_counters()
            self.start_time = current_time

        # 2. DATA EXTRACTION
        src_ip = packet_data.get('src')
        dst_port = packet_data.get('dst_port')

        # If it's a non-IP packet (like ARP), ignore it
        if not src_ip:
            return None

        # ------------------------------------------------------
        # RULE 1: SYN FLOOD DETECTION (DDoS)
        # ------------------------------------------------------
        self.ip_traffic[src_ip] += 1
        
        if self.ip_traffic[src_ip] > self.FLOOD_THRESHOLD:
            # We return an alert immediately
            return f"[!] FLOOD DETECTED: {src_ip} is sending {self.ip_traffic[src_ip]} pkts/sec"

        # ------------------------------------------------------
        # RULE 2: PORT SCAN DETECTION (Reconnaissance)
        # ------------------------------------------------------
        if dst_port:
            self.port_scan_map[src_ip].add(dst_port)
            
            # Check the size of the set (number of unique ports)
            unique_ports = len(self.port_scan_map[src_ip])
            if unique_ports > self.SCAN_THRESHOLD:
                return f"[!] PORT SCAN DETECTED: {src_ip} hit {unique_ports} unique ports"

        # If no rules are broken, return nothing
        return None

    def reset_counters(self):
        """Clears memory to start a new second."""
        self.ip_traffic.clear()
        self.port_scan_map.clear()