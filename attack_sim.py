import time
import random
import socket
from scapy.all import IP, TCP, send, get_if_addr, conf, get_if_list

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

def simulate_port_scan(target_ip=None, count=20, src_ip=None):
    """
    Simulate a port scan attack that will be detected by NetGuard.
    
    Args:
        target_ip: Target IP address (defaults to local IP)
        count: Number of packets to send (default 20, should trigger port scan alert at 15)
        src_ip: Source IP to use (defaults to local IP)
    """
    if target_ip is None:
        target_ip = get_local_ip()
    if src_ip is None:
        src_ip = get_local_ip()
    
    print(f"[*] Starting SYN Port Scan Simulation...")
    print(f"    Source IP: {src_ip}")
    print(f"    Target IP: {target_ip}")
    print(f"    Packets: {count} (Threshold: 15 unique ports)")
    
    # Use a fake external IP for better testing (simulates external attacker)
    # This helps test the detection logic more realistically
    fake_src_ip = "192.168.66.6"  # Fake attacker IP
    
    # Get the interface that NetGuard is likely using
    sniff_iface = get_sniffing_interface()
    if sniff_iface:
        print(f"    Using interface: {sniff_iface}")
    
    ports_sent = []
    for i in range(count):
        dst_port = random.randint(1024, 65535)
        ports_sent.append(dst_port)
        
        # Craft a TCP SYN packet with explicit source IP
        # Using fake_src_ip so it's detected as an external attacker
        pkt = IP(src=fake_src_ip, dst=target_ip)/TCP(sport=random.randint(49152, 65535), dport=dst_port, flags="S")
        
        # Try to send on the sniffing interface first, then fallback
        sent = False
        if sniff_iface:
            try:
                send(pkt, verbose=0, iface=sniff_iface)
                sent = True
            except:
                pass
        
        if not sent:
            try:
                # Try default interface
                send(pkt, verbose=0, iface=conf.iface)
            except:
                try:
                    # Last resort: send without interface
                    send(pkt, verbose=0)
                except Exception as e:
                    if i == 0:  # Only print error on first packet
                        print(f"    Warning: Could not send packets: {e}")
                        print(f"    Make sure you have admin privileges and NetGuard is running!")
        
        # Small delay to spread packets over time (allows sniffer to capture)
        time.sleep(0.05)
        
    print(f"[+] Scan Complete. Sent {count} packets to {len(set(ports_sent))} unique ports.")
    print(f"    Unique ports: {len(set(ports_sent))}")
    print("    Check your NetGuard dashboard for 'PORT SCAN' alerts.")
    print("    Note: Make sure NetGuard is running and sniffing before running this script!")

def simulate_flood_attack(target_ip=None, count=1600, src_ip=None):
    """
    Simulate a flood attack (DDoS).
    
    Args:
        target_ip: Target IP address (defaults to local IP)
        count: Number of packets to send (default 1600, should trigger flood alert at 1500)
        src_ip: Source IP to use (defaults to fake attacker IP)
    """
    if target_ip is None:
        target_ip = get_local_ip()
    if src_ip is None:
        src_ip = "192.168.66.6"  # Fake attacker IP
    
    print(f"[*] Starting Flood Attack Simulation...")
    print(f"    Source IP: {src_ip}")
    print(f"    Target IP: {target_ip}")
    print(f"    Packets: {count} (Threshold: 1500 pkts/sec)")
    
    # Get the interface that NetGuard is likely using
    sniff_iface = get_sniffing_interface()
    
    for i in range(count):
        pkt = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(49152, 65535), dport=80, flags="S")
        
        # Try to send on the sniffing interface first
        sent = False
        if sniff_iface:
            try:
                send(pkt, verbose=0, iface=sniff_iface)
                sent = True
            except:
                pass
        
        if not sent:
            try:
                send(pkt, verbose=0, iface=conf.iface)
            except:
                try:
                    send(pkt, verbose=0)
                except:
                    pass
        
        # Send packets quickly to simulate flood (but with tiny delay for capture)
        if i % 100 == 0:
            print(f"    Sent {i}/{count} packets...")
        time.sleep(0.001)  # Tiny delay to allow capture
    
    print(f"[+] Flood Complete. Sent {count} packets.")
    print("    Check your NetGuard dashboard for 'FLOOD DETECTED' alerts.")

if __name__ == "__main__":
    print("--- NetGuard Attack Simulator ---")
    print("1. Port Scan Simulation (20 packets)")
    print("2. Flood Attack Simulation (1600 packets)")
    
    local_ip = get_local_ip()
    print(f"\nDetected Local IP: {local_ip}")
    print("Note: Make sure NetGuard dashboard is running and sniffing before executing attacks!\n")
    
    choice = input("Select attack type (1=Port Scan, 2=Flood, default=1): ").strip()
    if not choice:
        choice = "1"
    
    target = input(f"Enter Target IP (default={local_ip}): ").strip()
    if not target:
        target = local_ip
    
    if choice == "2":
        simulate_flood_attack(target)
    else:
        simulate_port_scan(target)
