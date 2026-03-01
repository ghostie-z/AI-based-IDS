# 🛡️ Universal AI-Powered Host Intrusion Detection System (HIDS)

A cross-platform, real-time Network Intrusion Detection System that uses **Machine Learning (Random Forest)** to identify and mitigate DoS and Web-based attacks. This system is designed to run seamlessly on **Windows, Linux, and macOS**.

---

## ⚠️ Critical Requirement: Privileged Access
This application requires direct access to your network hardware to "sniff" packets. It **must** be run with elevated privileges:
* **Windows:** Open PowerShell or Command Prompt as **Administrator**.
* **Linux/macOS:** Execute the script using `sudo`.

---

## 🚀 Key Features
- **OS-Agnostic Core:** Automatically detects the operating system and adjusts network interface handling.
- **Dynamic Thresholding:** Uses **Context-Aware Logic** to separate Internal/Local traffic (High Trust) from External/Incoming traffic (High Sensitivity).
- **AI-Driven Inference:** Processes 25 unique network features through a trained Random Forest model.
- **Automatic Interface Selection:** Leverages Scapy's `conf` engine to find the active internet connection automatically.

---

## 🛠️ System Requirements

### 1. Packet Capture Drivers (Required for every device)
Before running the script, your OS needs a driver to allow Python to see raw network traffic:
* **Windows:** Install [Npcap](https://nmap.org/npcap/) (Select "Install Npcap in WinPcap API-compatible Mode").
* **Linux:** Install libpcap (`sudo apt install libpcap-dev`).
* **macOS:** Ensure `libpcap` is installed (usually default, or via `brew install libpcap`).

### 2. Python Dependencies
```bash
pip install pandas numpy scapy joblib scikit-learn

```

*Note: Linux users may also need `sudo apt install python3-tk` for GUI support.*

---

## 🚦 Smart Threshold Logic

To minimize False Positives, the IDS applies different sensitivity levels based on the traffic source:

| Traffic Zone | Threshold | Description |
| --- | --- | --- |
| **Incoming** | **7% - 15%** | High sensitivity for external threats (DoS/Web Attacks). |
| **Internal** | **40%** | High trust for local loopback and system-to-system traffic. |

---

## 💻 How to Run

### Windows (Administrator)

1. Right-click **PowerShell** -> **Run as Administrator**.
2. Navigate to the folder.
3. `python hids.py`

### Linux/macOS (Root)

1. Open Terminal.
2. `sudo python3 hids.py`

---

## 📊 Feature Extraction Engine

The model analyzes the following **25 critical features** from every network flow:

* **IAT (Inter-Arrival Time):** Mean, Max, and Min gaps between packets.
* **Payload Metrics:** Total Bwd Packet Length, Average Packet Size.
* **TCP Flags:** PSH and ACK flag counts to detect exploit attempts.
* **Window Size:** `Init_Win_bytes` for OS fingerprinting and botnet detection.

---

## 📈 Expected Results

* **Normal Traffic:** 🟢 BENIGN (Score below threshold)
* **Simulated Attack:** 🚨 ALERT: [Attack Type] (Score above threshold)



