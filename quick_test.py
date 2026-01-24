"""
NetGuard Quick Test Script
===========================
This script helps you quickly test if NetGuard is detecting attacks correctly.

Usage:
    1. Start NetGuard (python main.py) and click "Start Sniffing"
    2. Run this script in a separate admin terminal
    3. Choose test type and observe dashboard alerts
"""

import time
import socket
from scapy.all import IP, TCP, send, conf
import sys

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

def test_port_scan(target_ip, num_ports=20):
    """
    Test 1: Port Scan Detection
    Expected: Alert after 15+ unique ports
    """
    print("\n" + "="*60)
    print("TEST 1: PORT SCAN DETECTION")
    print("="*60)
    print(f"Target: {target_ip}")
    print(f"Ports to scan: {num_ports}")
    print(f"Expected: Alert after 15 ports")
    print(f"Rule: PORT SCAN: ... accessed {num_ports} unique ports")
    print("="*60)
    
    input("\n⚠️  Make sure NetGuard is RUNNING and SNIFFING. Press Enter to start...")
    
    fake_attacker = "192.168.66.6"
    ports_scanned = []
    
    print(f"\n[*] Simulating port scan from {fake_attacker}...")
    for i in range(num_ports):
        port = 1024 + i  # Sequential ports for clarity
        ports_scanned.append(port)
        
        pkt = IP(src=fake_attacker, dst=target_ip)/TCP(sport=54321, dport=port, flags="S")
        try:
            send(pkt, verbose=0)
            if (i + 1) % 5 == 0:
                print(f"    Sent {i+1}/{num_ports} packets...")
        except Exception as e:
            print(f"    Error sending packet: {e}")
            print(f"    Make sure you're running as Administrator!")
            return
        
        time.sleep(0.05)  # Small delay for capture
    
    print(f"\n✅ Test Complete!")
    print(f"   Scanned {len(set(ports_scanned))} unique ports")
    print(f"\n📊 Check NetGuard Dashboard:")
    print(f"   - Look for 'PORT SCAN' alert")
    print(f"   - Source IP should be: {fake_attacker}")
    print(f"   - Alert should show: 'accessed {num_ports} unique ports'")

def test_flood_attack(target_ip, num_packets=1600):
    """
    Test 2: Flood/DDoS Detection
    Expected: Alert after 1500 packets
    """
    print("\n" + "="*60)
    print("TEST 2: FLOOD/DDoS DETECTION")
    print("="*60)
    print(f"Target: {target_ip}")
    print(f"Packets to send: {num_packets}")
    print(f"Expected: Alert after 1500 packets/sec")
    print(f"Rule: FLOOD DETECTED: ... sending {num_packets} pkts/sec")
    print("="*60)
    
    input("\n⚠️  Make sure NetGuard is RUNNING and SNIFFING. Press Enter to start...")
    
    fake_attacker = "192.168.66.6"
    
    print(f"\n[*] Simulating flood attack from {fake_attacker}...")
    start_time = time.time()
    
    for i in range(num_packets):
        pkt = IP(src=fake_attacker, dst=target_ip)/TCP(sport=54321, dport=80, flags="S")
        try:
            send(pkt, verbose=0)
            if (i + 1) % 200 == 0:
                print(f"    Sent {i+1}/{num_packets} packets...")
        except Exception as e:
            print(f"    Error sending packet: {e}")
            print(f"    Make sure you're running as Administrator!")
            return
        
        time.sleep(0.0005)  # Very small delay to allow capture
    
    elapsed = time.time() - start_time
    rate = num_packets / elapsed
    
    print(f"\n✅ Test Complete!")
    print(f"   Sent {num_packets} packets in {elapsed:.2f} seconds")
    print(f"   Rate: {rate:.0f} packets/sec")
    print(f"\n📊 Check NetGuard Dashboard:")
    print(f"   - Look for 'FLOOD DETECTED' alert")
    print(f"   - Source IP should be: {fake_attacker}")
    print(f"   - Alert should show packet count > 1500")

def test_normal_traffic(target_ip, num_packets=10):
    """
    Test 3: Normal Traffic (Should NOT trigger alerts)
    Expected: No alerts, marked as "Normal"
    """
    print("\n" + "="*60)
    print("TEST 3: NORMAL TRAFFIC (Baseline)")
    print("="*60)
    print(f"Target: {target_ip}")
    print(f"Packets to send: {num_packets}")
    print(f"Expected: NO alerts, traffic marked as 'Normal'")
    print("="*60)
    
    input("\n⚠️  Make sure NetGuard is RUNNING and SNIFFING. Press Enter to start...")
    
    local_ip = get_local_ip()
    
    print(f"\n[*] Simulating normal traffic from {local_ip}...")
    for i in range(num_packets):
        pkt = IP(src=local_ip, dst=target_ip)/TCP(sport=54321, dport=80, flags="S")
        try:
            send(pkt, verbose=0)
            print(f"    Sent {i+1}/{num_packets} packets...")
        except Exception as e:
            print(f"    Error: {e}")
            return
        
        time.sleep(0.5)  # Slow, normal rate
    
    print(f"\n✅ Test Complete!")
    print(f"\n📊 Check NetGuard Dashboard:")
    print(f"   - Should see {num_packets} packets in traffic log")
    print(f"   - Anomaly column should show 'Normal'")
    print(f"   - NO alerts should appear")
    print(f"   - If alerts appear, thresholds may be too sensitive")

def diagnostic_check():
    """
    Run diagnostic checks before testing
    """
    print("\n" + "="*60)
    print("DIAGNOSTIC CHECK")
    print("="*60)
    
    # Check if running as admin
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            print("✅ Running as Administrator")
        else:
            print("❌ NOT running as Administrator")
            print("   Please restart terminal as Administrator!")
            return False
    except:
        print("⚠️  Could not verify admin status")
    
    # Check Scapy
    try:
        from scapy.all import conf
        print(f"✅ Scapy installed")
        print(f"   Default interface: {conf.iface}")
    except ImportError:
        print("❌ Scapy not installed")
        print("   Run: pip install scapy")
        return False
    
    # Check local IP
    local_ip = get_local_ip()
    print(f"✅ Local IP detected: {local_ip}")
    
    print("\n" + "="*60)
    print("BEFORE TESTING:")
    print("1. Start NetGuard: python main.py")
    print("2. Click 'Start Sniffing' button")
    print("3. Wait for console message: '[Network Engine] Sniffer started.'")
    print("4. Then run tests from this script")
    print("="*60)
    
    return True

def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║         NetGuard Quick Test Script                        ║
║         Test your DDoS detection system                   ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Run diagnostics first
    if not diagnostic_check():
        print("\n❌ Diagnostic check failed. Fix issues before testing.")
        sys.exit(1)
    
    local_ip = get_local_ip()
    
    print("\n\nSelect Test:")
    print("1. Port Scan Detection (20 packets to unique ports)")
    print("2. Flood/DDoS Detection (1600 packets)")
    print("3. Normal Traffic Baseline (10 packets, slow rate)")
    print("4. Run All Tests (Sequential)")
    print("5. Custom Test")
    
    choice = input("\nEnter choice (1-5, default=1): ").strip()
    if not choice:
        choice = "1"
    
    target = input(f"Target IP (default={local_ip}): ").strip()
    if not target:
        target = local_ip
    
    print(f"\n🎯 Target IP: {target}")
    
    if choice == "1":
        test_port_scan(target)
    elif choice == "2":
        test_flood_attack(target)
    elif choice == "3":
        test_normal_traffic(target)
    elif choice == "4":
        print("\n🔄 Running all tests sequentially...\n")
        test_normal_traffic(target)
        time.sleep(2)
        test_port_scan(target)
        time.sleep(2)
        test_flood_attack(target)
    elif choice == "5":
        num = int(input("Number of packets: "))
        delay = float(input("Delay between packets (seconds): "))
        print(f"\n[*] Sending {num} packets with {delay}s delay...")
        for i in range(num):
            pkt = IP(src="192.168.66.6", dst=target)/TCP(dport=80, flags="S")
            send(pkt, verbose=0)
            time.sleep(delay)
        print("✅ Done!")
    else:
        print("Invalid choice")
    
    print("\n\n" + "="*60)
    print("NEXT STEPS:")
    print("1. Check NetGuard dashboard for alerts")
    print("2. Review traffic log for packet details")
    print("3. If no alerts appear, see TESTING_GUIDE.md troubleshooting")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        print("Make sure you're running as Administrator!")
