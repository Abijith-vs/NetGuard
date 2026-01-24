import time
from collections import defaultdict

class LogicEngine:
    def __init__(self, flood_threshold=3000, scan_threshold=25, window_size=2.0):
        """
        Initialize Logic Engine with configurable detection thresholds.
        
        Args:
            flood_threshold: Packets per second to trigger flood alert (default: 3000)
            scan_threshold: Unique ports accessed to trigger scan alert (default: 25)
            window_size: Time window in seconds for sliding window (default: 2.0)
        
        Note: Default values increased from original (1500/15/1.0) to reduce false positives
              on modern networks with high background traffic.
        """
        # --- CONFIGURATION ---
        self.FLOOD_THRESHOLD = flood_threshold
        self.SCAN_THRESHOLD = scan_threshold
        self.WINDOW_SIZE = window_size
        
        # FIX: Whitelist for common legitimate traffic patterns
        # These IPs/ports won't trigger alerts (reduce false positives)
        self.whitelist_ips = set()  # Add trusted IPs here: {'192.168.1.1', '8.8.8.8'}
        self.whitelist_ports = {80, 443, 53, 22, 21, 25, 587, 993, 995}  # Common legitimate ports
        
        # Sliding window: store timestamps instead of simple counts
        self.ip_traffic_timestamps = defaultdict(list)  # {ip: [timestamps]}
        self.port_scan_timestamps = defaultdict(lambda: defaultdict(list))  # {ip: {port: [timestamps]}}
        self.lock = None  # Will be set if threading is needed

    def _cleanup_old_entries(self, current_time):
        """Remove entries older than WINDOW_SIZE from sliding windows"""
        cutoff_time = current_time - self.WINDOW_SIZE
        
        # Cleanup flood detection timestamps
        for ip in list(self.ip_traffic_timestamps.keys()):
            self.ip_traffic_timestamps[ip] = [
                t for t in self.ip_traffic_timestamps[ip] if t > cutoff_time
            ]
            if not self.ip_traffic_timestamps[ip]:
                del self.ip_traffic_timestamps[ip]
        
        # Cleanup port scan timestamps
        for ip in list(self.port_scan_timestamps.keys()):
            for port in list(self.port_scan_timestamps[ip].keys()):
                self.port_scan_timestamps[ip][port] = [
                    t for t in self.port_scan_timestamps[ip][port] if t > cutoff_time
                ]
                if not self.port_scan_timestamps[ip][port]:
                    del self.port_scan_timestamps[ip][port]
            if not self.port_scan_timestamps[ip]:
                del self.port_scan_timestamps[ip]

    def check_packet(self, packet_data):
        """
        Check packet against detection rules using sliding window approach.
        
        Returns:
            None if no alert, or alert message string if attack detected
        """
        current_time = time.time()
        src_ip = packet_data.get('src')
        dst_port = packet_data.get('dst_port')

        if not src_ip:
            return None

        # FIX: Skip whitelisted IPs to reduce false positives
        if src_ip in self.whitelist_ips:
            return None

        # Cleanup old entries (sliding window)
        self._cleanup_old_entries(current_time)

        # RULE 1: FLOOD DETECTION
        # Count packets from this IP in the time window
        self.ip_traffic_timestamps[src_ip].append(current_time)
        packet_count = len(self.ip_traffic_timestamps[src_ip])
        
        if packet_count > self.FLOOD_THRESHOLD:
            return f"FLOOD DETECTED: {src_ip} sending {packet_count} pkts/sec (threshold: {self.FLOOD_THRESHOLD})"

        # RULE 2: PORT SCAN DETECTION
        if dst_port:
            # FIX: Ignore whitelisted ports (common legitimate ports)
            if dst_port in self.whitelist_ports:
                return None
            
            # Track this port access
            self.port_scan_timestamps[src_ip][dst_port].append(current_time)
            
            # Count unique ports accessed by this IP in the time window
            # FIX: Only count non-whitelisted ports for scan detection
            non_whitelisted_ports = {p for p in self.port_scan_timestamps[src_ip].keys() 
                                     if p not in self.whitelist_ports}
            unique_ports = len(non_whitelisted_ports)
            
            if unique_ports > self.SCAN_THRESHOLD:
                return f"PORT SCAN: {src_ip} accessed {unique_ports} unique ports (threshold: {self.SCAN_THRESHOLD})"

        return None

    def update_thresholds(self, flood=None, scan=None, window=None):
        """
        Update detection thresholds at runtime.
        
        Args:
            flood: New flood threshold (pkts/sec), None to keep current
            scan: New scan threshold (unique ports), None to keep current
            window: New window size (seconds), None to keep current
        """
        if flood is not None:
            self.FLOOD_THRESHOLD = flood
            print(f"[LogicEngine] FLOOD_THRESHOLD updated to {flood}")
        if scan is not None:
            self.SCAN_THRESHOLD = scan
            print(f"[LogicEngine] SCAN_THRESHOLD updated to {scan}")
        if window is not None:
            self.WINDOW_SIZE = window
            print(f"[LogicEngine] WINDOW_SIZE updated to {window}")
    
    def add_whitelist_ip(self, ip):
        """Add an IP to the whitelist (won't trigger alerts)"""
        self.whitelist_ips.add(ip)
        print(f"[LogicEngine] Added {ip} to whitelist")
    
    def remove_whitelist_ip(self, ip):
        """Remove an IP from the whitelist"""
        self.whitelist_ips.discard(ip)
        print(f"[LogicEngine] Removed {ip} from whitelist")
    
    def reset_counters(self):
        """Reset all counters (for testing or manual reset)"""
        self.ip_traffic_timestamps.clear()
        self.port_scan_timestamps.clear()