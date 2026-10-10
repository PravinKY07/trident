"""
sim_miner.py - benign miner simulator for TRIDENT demo.
No actual mining. No auth to any pool. Just the behavioral fingerprint:
CPU spin + repeated TCP connects to a known mining pool hostname.
"""
import socket, threading, time, sys

POOL_HOST = "pool.supportxmr.com"
POOL_PORT = 3333
CPU_THREADS = 4
DURATION = 90

def spin():
    end = time.time() + DURATION
    x = 0
    while time.time() < end:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF

def beacon():
    end = time.time() + DURATION
    while time.time() < end:
        try:
            s = socket.create_connection((POOL_HOST, POOL_PORT), timeout=3)
            s.close()
        except Exception:
            pass
        time.sleep(3)

if __name__ == "__main__":
    print(f"[sim_miner] stratum+tcp://{POOL_HOST}:{POOL_PORT}", flush=True)
    print("[sim_miner] user=44AFFq5kSiGBoZ...  algo=rx/0", flush=True)
    threading.Thread(target=beacon, daemon=True).start()
    for _ in range(CPU_THREADS):
        threading.Thread(target=spin, daemon=True).start()
    time.sleep(DURATION)