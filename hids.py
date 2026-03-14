import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, IP, TCP, UDP
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
import warnings
import sys
from collections import defaultdict
import time
from scapy.all import get_if_list
import os

def choose_interface():
    interfaces = get_if_list()

    print("\n--- 🌐 Available Network Interfaces ---")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")

    while True:
        choice = input("\nSelect interface number (Enter for default): ")
        if choice == "":
            # This uses Scapy's internal 'conf' to find the best card automatically
            return conf.iface 
        try:
            idx = int(choice)
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
        except:
            pass
        print("Invalid selection. Try again.")

flow_table = {}

class Flow:
    def __init__(self):
        self.start_time = time.time()
        self.last_time = self.start_time

        self.fwd_lengths = []
        self.bwd_lengths = []

        self.flow_iat = []
        self.fwd_iat = []
        self.bwd_iat = []

        self.last_fwd_time = None
        self.last_bwd_time = None

        self.psh_count = 0
        self.ack_count = 0

        self.init_win_fwd = 0
        self.init_win_bwd = 0

# 1. Setup and Suppress Warnings
warnings.filterwarnings("ignore")

# 2. Setup Auto-Rotating Logging (Keeps last 90 days)
log_filename = "ids_report.log"
handler = TimedRotatingFileHandler(
    log_filename, when="D", interval=1, backupCount=90
)
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='%(message)s'
)

# 3. Load the AI Models
try:
    print("--- 🧠 Initializing IDS AI Engine ---")
    rf_model = joblib.load('random_forest_model.joblib')
    scaler = joblib.load('standard_scaler.joblib')
    le = joblib.load('label_encoder.joblib')
    print("✅ System Ready. Monitoring Live Traffic...")
except Exception as e:
    print(f"❌ Initialization Error: {e}")
    sys.exit()

# 4. Feature Extraction (Packet to AI Vector)
# ... (Keep your imports and Flow class the same) ...

FEATURES = [
    'Total Length of Bwd Packets', 'Fwd Packet Length Min', 'Bwd Packet Length Min', 
    'Bwd Packet Length Std', 'Flow IAT Mean', 'Flow IAT Min', 'Fwd IAT Min', 
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Min', 'Fwd Packets/s', 
    'Bwd Packets/s', 'Min Packet Length', 'Packet Length Variance', 'PSH Flag Count', 
    'ACK Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 
    'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 
    'Active Mean', 'Idle Min'
]

def extract_features(flow):
    # Ensure variables are arrays for math
    fwd = np.array(flow.fwd_lengths) if flow.fwd_lengths else np.array([0])
    bwd = np.array(flow.bwd_lengths) if flow.bwd_lengths else np.array([0])
    flow_iat = np.array(flow.flow_iat) if flow.flow_iat else np.array([0])
    fwd_iat = np.array(flow.fwd_iat) if flow.fwd_iat else np.array([0])
    bwd_iat = np.array(flow.bwd_iat) if flow.bwd_iat else np.array([0])

    duration = max(time.time() - flow.start_time, 1e-6)
    all_packets = np.concatenate([fwd, bwd])

    # The 25 Features in the EXACT order your scaler wants
    feat_values = [
        np.sum(bwd),                         # Total Length of Bwd Packets
        np.min(fwd),                         # Fwd Packet Length Min
        np.min(bwd),                         # Bwd Packet Length Min
        np.std(bwd),                         # Bwd Packet Length Std
        np.mean(flow_iat),                   # Flow IAT Mean
        np.min(flow_iat),                    # Flow IAT Min
        np.min(fwd_iat),                     # Fwd IAT Min
        np.sum(bwd_iat),                     # Bwd IAT Total
        np.mean(bwd_iat),                    # Bwd IAT Mean
        np.std(bwd_iat),                     # Bwd IAT Std
        np.min(bwd_iat),                     # Bwd IAT Min
        len(fwd) / duration,                 # Fwd Packets/s
        len(bwd) / duration,                 # Bwd Packets/s
        np.min(all_packets),                 # Min Packet Length
        np.var(all_packets),                 # Packet Length Variance
        flow.psh_count,                      # PSH Flag Count
        flow.ack_count,                      # ACK Flag Count
        len(bwd) / max(len(fwd), 1),         # Down/Up Ratio
        np.mean(all_packets),                # Average Packet Size
        np.mean(fwd),                        # Avg Fwd Segment Size
        np.sum(fwd),                         # Subflow Fwd Bytes
        flow.init_win_fwd,                   # Init_Win_bytes_forward
        flow.init_win_bwd,                   # Init_Win_bytes_backward
        np.mean(flow_iat),                   # Active Mean
        np.min(flow_iat)                     # Idle Min
    ]

    # Return as DataFrame with the 25 feature names defined earlier
    return pd.DataFrame([feat_values], columns=FEATURES)

# --- ADD THIS OUTSIDE THE FUNCTION ONCE ---
import socket
def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

MY_IP = get_my_ip()
# ------------------------------------------

def process_packet(packet):
    print(".", end="", flush=True)
    try:
        if not packet.haslayer(IP): return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else None
        if not protocol: return
        
        src_port = packet[protocol].sport
        dst_port = packet[protocol].dport

        # --- DIRECTION DETECTION ---
        if dst_ip == MY_IP:
            direction = "INCOMING"
        elif src_ip == MY_IP:
            direction = "OUTGOING"
        else:
            direction = "INTERNAL" # For loopback/local
        # ---------------------------

        # --- PROTECTED PORT PROBE (Port 4776) ---
        PROTECTED_PORT = 4776
        if dst_port == PROTECTED_PORT:
            timestamp = datetime.now().strftime("%H:%M:%S")
            probe_alert = (
                f"[{timestamp}] ⚠️ RULE-BASED ALERT: Unauthorized Probe on Port {PROTECTED_PORT} | "
                f"({direction}) | {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            )
            print(f"\r{probe_alert}")
            logging.info(probe_alert)
        # ----------------------------------------

        # Bidirectional Flow ID
        ip_pair = tuple(sorted((src_ip, dst_ip)))
        port_pair = tuple(sorted((src_port, dst_port)))
        flow_id = (ip_pair, port_pair, protocol)

        if flow_id not in flow_table:
            flow_table[flow_id] = Flow()
        
        flow = flow_table[flow_id]
        current_time = time.time()
        packet_len = len(packet)
        is_fwd = (src_ip == ip_pair[0])

        # Update Flow Stats
        flow.flow_iat.append(current_time - flow.last_time)
        flow.last_time = current_time

        if is_fwd:
            flow.fwd_lengths.append(packet_len)
            if flow.last_fwd_time: flow.fwd_iat.append(current_time - flow.last_fwd_time)
            flow.last_fwd_time = current_time
        else:
            flow.bwd_lengths.append(packet_len)
            if flow.last_bwd_time: flow.bwd_iat.append(current_time - flow.last_bwd_time)
            flow.last_bwd_time = current_time
            
        # --- AI INFERENCE ---
        if len(flow.fwd_lengths) > 0:
            feat_df = extract_features(flow)
            scaled_features = scaler.transform(feat_df)
            probs = rf_model.predict_proba(scaled_features)[0]
            
            benign_idx = list(le.classes_).index('BENIGN')
            benign_score = probs[benign_idx]
            suspicion_score = 1 - benign_score

            attack_probs = probs.copy()
            attack_probs[benign_idx] = -1 
            best_attack_idx = np.argmax(attack_probs)
            potential_attack = le.classes_[best_attack_idx] 

            if any(x in potential_attack for x in ["DDoS", "DoS", "DOS"]):
                mapped_verdict = "DOS"
                current_threshold = 0.27
            elif "Web Attack" in potential_attack:
                mapped_verdict = "WEB_ATTACK"
                current_threshold = 0.25 
            else:
                mapped_verdict = potential_attack
                current_threshold = 0.20

            if direction == "INTERNAL":
                current_threshold = 0.40 

            # Final Verdict Decision
            if suspicion_score > current_threshold:
                prefix = "🚨 ALERT"
                verdict = mapped_verdict
            else:
                prefix = "🟢 NORMAL"
                verdict = "BENIGN"

            timestamp = datetime.now().strftime("%H:%M:%S")
            output = (
                f"[{timestamp}] {prefix}: {verdict} | "
                f"({direction}) | " 
                f"Suspicion: {suspicion_score*100:.1f}% | "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            )
            
            print(f"\r{output}")
            if verdict != "BENIGN":
                logging.info(output)

    except Exception as e:
        pass
# 6. Automated Interface Selection & Sniffing Start
if __name__ == "__main__":
    # --- CROSS-PLATFORM PERMISSION CHECK ---
    is_admin = False
    if sys.platform.startswith('win'):
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.getuid() == 0

    if not is_admin:
        print("❌ ERROR: You must run this as Administrator (Windows) or Sudo (Linux/Mac).")
        sys.exit(1)

    warnings.filterwarnings("ignore")

    # Load Models
    try:
        print("--- 🧠 Initializing IDS AI Engine ---")
        rf_model = joblib.load('random_forest_model.joblib')
        scaler = joblib.load('standard_scaler.joblib')
        le = joblib.load('label_encoder.joblib')
    except Exception as e:
        print(f"❌ Load Error: {e}")
        sys.exit(1)

    # Use Scapy's cross-platform interface selector
    target_interface = choose_interface() 
    print(f"\n[SYSTEM] Monitoring: {target_interface} | Local IP: {MY_IP}")

    try:
        sniff(
            iface=target_interface,
            prn=process_packet,
            store=0,
            promisc=True
        )
    except KeyboardInterrupt:
        print("\n[STOPPED] Session terminated.")