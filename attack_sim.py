import time
import random
import socket
from scapy.all import IP, TCP, send, get_if_addr, conf, get_if_list, Ether, sendp, getmacbyip, srp, ARP

def get_local_ip():
    """Get the local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def get_sniffing_interface():
    """Get the interface that NetGuard would use for sniffing"""
    try:
        # Same logic as network_engine.py
        best_iface = conf.route.route("8.8.8.8")[0]
        return best_iface
    except:
        # Fallback to first available interface
        ifaces = get_if_list()
        if ifaces:
            return ifaces[0]
        return None

def resolve_gateway_mac(target_ip):
    """
    Resolve the MAC address of the next hop (Gateway) for a given target IP.
    """
    try:
        # Ask Scapy's routing table who is the next hop
        # returns: (iface, output_ip, gateway_ip)
        route = conf.route.route(target_ip)
        iface = route[0]
        gw_ip = route[2]
        
        if gw_ip == "0.0.0.0": # Local link
            gw_ip = target_ip
            
        print(f"    [debug] Route to {target_ip} via {gw_ip} on {iface}")
        
        # Try to resolve MAC
        mac = getmacbyip(gw_ip)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            return mac, iface
            
        # If Scapy failed, try manual ARP
        print(f"    [debug] Scapy failed to resolve MAC for {gw_ip}. Retrying with ARP...")
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw_ip), timeout=2, iface=iface, verbose=0)
            if ans:
                return ans[0][1].hwsrc, iface
        except Exception as e:
            print(f"    [debug] ARP failed: {e}")
            
        return None, iface
    except Exception as e:
        print(f"    [debug] Route resolution failed: {e}")
        return None, None

def simulate_port_scan(target_ip=None, count=20, src_ip=None):
    if target_ip is None: target_ip = "8.8.8.8"
    if src_ip is None: src_ip = get_local_ip() # Use Real IP for reliability
    
    print(f"[*] Starting SYN Port Scan Simulation...")
    print(f"    Source IP: {src_ip}")
    print(f"    Target IP: {target_ip}")
    
    # Resolve Gateway MAC
    gw_mac, iface = resolve_gateway_mac(target_ip)
    
    ports_sent = []
    for i in range(count):
        dst_port = random.randint(1024, 65535)
        ports_sent.append(dst_port)
        
        # Build Packet
        if gw_mac:
            # Golden Path: Layer 2 Unicast to Gateway
            pkt = Ether(dst=gw_mac)/IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(49152, 65535), dport=dst_port, flags="S")
            try:
                if iface:
                    sendp(pkt, iface=iface, verbose=0)
                else:
                    sendp(pkt, verbose=0)
            except Exception as e:
                if i == 0: print(f"    [!] L2 Send failed, switching to L3: {e}")
                start_l3_fallback = True
        else:
            # Fallback: Layer 3 (Let Scapy/OS handle routing)
            # This might cause "MAC not found" warnings but is better than L2 Broadcast
            if i == 0: print(f"    [!] Gateway MAC unknown. Using Layer 3 fallback (may show warnings)...")
            pkt = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(49152, 65535), dport=dst_port, flags="S")
            try:
                send(pkt, verbose=0)
            except:
                pass
        
        time.sleep(0.05)
        
    print(f"[+] Scan Complete. Sent {count} packets.")
    print("    Check NetGuard dashboard.")

def simulate_flood_attack(target_ip=None, count=3000, src_ip=None):
    if target_ip is None: target_ip = "8.8.8.8"
    if src_ip is None: src_ip = "192.168.66.6" 
    
    print(f"[*] Starting Flood Attack Simulation...")
    print(f"    Target IP: {target_ip}")
    
    gw_mac, iface = resolve_gateway_mac(target_ip)
    
    if gw_mac:
        # Pre-build L2 packet
        base_pkt = Ether(dst=gw_mac)/IP(src=src_ip, dst=target_ip)/TCP(dport=80, flags="S")
    else:
        # Pre-build L3 packet
        print(f"    [!] Gateway MAC unknown. Using Layer 3 fallback...")
        base_pkt = IP(src=src_ip, dst=target_ip)/TCP(dport=80, flags="S")
    
    for i in range(count):
        pkt = base_pkt
        pkt[TCP].sport = random.randint(1024, 65535)
        
        try:
            if gw_mac:
                if iface: sendp(pkt, iface=iface, verbose=0)
                else: sendp(pkt, verbose=0)
            else:
                send(pkt, verbose=0)
        except:
             pass
             
        if i % 500 == 0:
            print(f"    Sent {i}/{count} packets...")
            
    print(f"[+] Flood Complete.")
    print("    Check NetGuard dashboard.")

if __name__ == "__main__":
    print("--- NetGuard Attack Simulator ---")
    print("1. Port Scan Simulation (20 packets)")
    print("2. Flood Attack Simulation (3000 packets)")
    
    local_ip = get_local_ip()
    print(f"\nDetected Local IP: {local_ip}")
    print("Note: Make sure NetGuard dashboard is running and sniffing before executing attacks!\n")
    
    choice = input("Select attack type (1=Port Scan, 2=Flood, default=1): ").strip()
    if not choice:
        choice = "1"
    
    # FIX: Default to external IP (8.8.8.8) instead of Local IP
    # Windows loopback traffic is often not captured by Scapy on physical adapters.
    # Sending to an external IP ensures packets hit the wire and are seen by the sniffer.
    print(f"Suggestion: Use '8.8.8.8' (Google DNS) as target to ensure packets are captured.")
    target = input(f"Enter Target IP (default=8.8.8.8): ").strip()
    if not target:
        target = "8.8.8.8"
    
    if choice == "2":
        simulate_flood_attack(target)
    else:
        simulate_port_scan(target)
