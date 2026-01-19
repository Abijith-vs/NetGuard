import time
from rule_engine import LogicEngine

def test_logic():
    print("--- STARTING DYNAMIC LOGIC TEST ---")
    engine = LogicEngine()
    
    # 1. Flood Test
    print("\n[TEST 1] Flood Simulation (105 packets in < 1s)")
    engine.reset_counters()
    engine.start_time = time.time()
    
    triggered = False
    for i in range(105):
        pkt = {'src': '10.0.0.1', 'dst_port': 80}
        alert = engine.check_packet(pkt)
        if alert:
             print(f"   -> Detected at packet {i+1}: {alert}")
             triggered = True
             break
    
    if triggers_expected := True:
        if triggered: print("   -> PASS: Flood detected.")
        else: print("   -> FAIL: Flood NOT detected.")

    # 2. Time Window Reset Test
    print("\n[TEST 2] Reset Counter Logic")
    engine.reset_counters()
    engine.start_time = time.time()
    
    # Send 50 packets (Half threshold)
    for _ in range(50):
        engine.check_packet({'src': '10.0.0.1', 'dst_port': 80})
    
    print("   -> Sent 50 packets. Waiting 1.1 seconds...")
    time.sleep(1.1)
    
    # Send 60 more packets. Total 110. But should NOT trigger because of reset.
    triggered_after_sleep = False
    for i in range(60):
        alert = engine.check_packet({'src': '10.0.0.1', 'dst_port': 80})
        if alert:
            triggered_after_sleep = True
            print(f"   -> Unexpected Alert: {alert}")
            break
            
    if not triggered_after_sleep:
        print("   -> PASS: Counters reset successfully after 1s.")
    else:
        print("   -> FAIL: Counters did not reset properly.")

    print("\n--- TEST COMPLETE ---")

if __name__ == "__main__":
    test_logic()
