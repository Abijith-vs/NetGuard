# **NetGuard: Real-Time Network Anomaly Detection System using Machine Learning**




## 🛡️ **Project Overview**


NetGuard is a Real-Time Network Detection System (NDS) designed to bridge the gap between raw data capture and automated security analysis. Unlike passive monitoring tools (such as Wireshark) that require manual expert interpretation, NetGuard actively analyzes live traffic to automatically identify security threats, specifically focusing on DDoS (Ping Floods) and Port Scanning.

## ✨ **Key Features**

Real-Time Sniffing: Uses the Python Scapy library in Promiscuous Mode to intercept all packets on the local network segment.

5-Tuple Feature Extraction: Decapsulates packets to extract critical flow identifiers: Source IP, Destination IP, Source Port, Destination Port, and Protocol (TCP/UDP/ICMP).

Hybrid Detection Engine:

Heuristic Analysis: Uses a Sliding Window Counter algorithm to detect volumetric attacks like DDoS.

Machine Learning: Implements the Isolation Forest algorithm to detect anomalies by isolating outliers in a random forest structure.

Modern Dashboard: A sleek desktop interface built with CustomTkinter, providing live traffic logs, instant security alerts, and system performance metrics.

Forensic Logging: Automatically exports analyzed traffic and alerts into structured CSV files for retrospective analysis and graphical reporting.

## 🛠️ **Tech Stack**

Language: Python

Network Capture: Scapy

Machine Learning: Scikit-learn (Isolation Forest)

Data Handling: Pandas, NumPy

GUI: CustomTkinter

Performance Monitoring: Psutil

Dataset: NSL-KDD (for training and benchmarking)

## 🚀 **System Architecture & Flow**

Data Acquisition: Raw binary frames are captured from the Network Interface Card (NIC).

Preprocessing: Data packets are parsed and transformed into a feature vector matching the NSL-KDD schema.

Anomaly Scoring: The Isolation Forest model calculates the "path length" for each packet. Shorter paths indicate high-probability anomalies.

Alerting: The GUI triggers a visual red alert when the anomaly score or statistical threshold is breached.

## 📊 **Expected Performance**
Accuracy: Projected between 90.0% and 95.6% based on NSL-KDD benchmarks for Isolation Forest.

Efficiency: Designed to be lightweight
 with real-time monitoring of CPU and RAM usage to ensure minimal system overhead.



# 🛡️ NetGuard: Real-Time Network Anomaly Detection System

NetGuard is a Real-Time Network Detection System (NDS) designed to bridge the gap between raw data capture and automated security analysis. Unlike passive monitoring tools (such as Wireshark) that require manual expert interpretation, NetGuard actively analyzes live traffic to automatically identify security threats, specifically focusing on DDoS (Ping Floods), Port Scanning, and Zero-Day anomalies.

---

## ✨ Key Features

- **Real-Time Sniffing**: Uses the Python `scapy` library in Promiscuous Mode to intercept all packets on the local network segment.
- **5-Tuple Feature Extraction**: Decapsulates packets to extract critical flow identifiers matching the NSL-KDD dataset schema (Source IP, Destination IP, Source Port, Destination Port, Protocol, and statistical flags).
- **Hybrid Detection Engine**:
  - **Heuristic Analysis**: Uses a Sliding Window Counter algorithm to detect volumetric attacks like DDoS.
  - **Supervised ML (Random Forest)**: Classifies known attack signatures using a highly accurate Random Forest model.
  - **Unsupervised ML (Isolation Forest)**: Detects zero-day anomalies by isolating outliers in a random forest structure, flagging traffic that deviates from normal baselines.
- **Modern Dashboard**: A sleek desktop interface built with `CustomTkinter`, providing live traffic logs, instant security alerts, and system performance metrics.
- **Forensic Logging**: Automatically exports analyzed traffic and alerts into structured CSV files for retrospective analysis and reporting.

---

## 📂 Project Structure

The codebase has been modularized and organized into a clean, professional structure:

```text
NetGuard/
│
├── src/                      # Core application source code
│   ├── main.py               # Main application and GUI startup
│   ├── gui_dashboard.py      # CustomTkinter dashboard implementation
│   ├── ml_engine.py          # Machine learning model loaders and prediction logic
│   ├── network_engine.py     # Scapy packet sniffer and feature extractor
│   └── rule_engine.py        # Heuristic sliding window rules (DoS, Port Scans)
│
├── models/                   # Pre-trained ML models and scalers
│   ├── iforest_model.pkl     # Isolation Forest (Zero-Day Detection)
│   ├── rf_model.pkl          # Random Forest (Supervised Classification)
│   ├── scaler.pkl            # StandardScaler for feature normalization
│   └── label_encoder.pkl     # Encoder for attack categories
│
├── scripts/                  # Training, evaluation, and simulation scripts
│   ├── train_supervised.py   # Trains the Random Forest model
│   ├── train_model.py        # Trains the Isolation Forest model
│   ├── evaluate_model.py     # Evaluates Random Forest performance
│   ├── evaluate_iforest.py   # Evaluates Isolation Forest performance
│   ├── flood_test.py         # Self-test script to simulate DDoS & Port Scans locally
│   ├── debug_model.py        # Debugging utility for ML models
│   ├── final_verify.py       # Integration check script
│   └── ...                   # Other unit and logic testing scripts
│
├── data/                     # Datasets
│   └── nsl-kdd/              # NSL-KDD dataset used for training and testing
│
├── run.py                    # Root execution script to launch NetGuard
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## 🛠️ Tech Stack

- **Language**: Python 3
- **Network Capture**: `scapy`
- **Machine Learning**: `scikit-learn`, `joblib`
- **Data Processing**: `pandas`, `numpy`
- **GUI**: `customtkinter`
- **Performance Monitoring**: `psutil`
- **Dataset**: [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) (for training and benchmarking)

---

## 🚀 Installation & Setup

**1. Clone the repository and navigate to the project directory:**
```bash
git clone <your-repository-url>
cd NetGuard
```

**2. Set up the Python virtual environment (optional but recommended):**
```bash
# If myenv doesn't exist, create it:
python3 -m venv myenv
source myenv/bin/activate  # On Linux/Mac
# .\myenv\Scripts\activate # On Windows
```

**3. Install the required dependencies:**
```bash
pip install -r requirements.txt
```

*(Note: Depending on your OS, `scapy` may require additional system-level packet capture tools like `tcpdump` or `Npcap`/`WinPcap`.)*

---

## 🖥️ Usage Guide

### 1. Running the NetGuard Dashboard
To launch the real-time monitoring dashboard, use the `run.py` script from the root directory. **You must run this as Administrator/root** to allow `scapy` to capture raw network packets.

```bash
sudo python3 run.py
```

### 2. Simulating Attacks (Self-Testing)
Want to see the detection engine in action? We provide a built-in attack simulator.
Open a **new terminal** (while NetGuard is running), ensure you have root privileges, and execute the flood test:

```bash
sudo python3 scripts/flood_test.py
```
This interactive script will allow you to simulate:
- **SYN Floods**
- **DDoS / Volume Floods**
- **Port Scans**

Watch the NetGuard dashboard trigger `MODERATE` or `CRITICAL` alerts in real-time!

---

## 🧪 System Verification and Testing

NetGuard includes a comprehensive suite of testing and verification scripts to ensure each component functions as expected. Run these scripts from the root directory to validate system integrity without launching the full dashboard:

### 1. Full Integration Check
Run a top-to-bottom check on module loading, logic rules, ML predictions, and network extraction:
```bash
python scripts/final_verify.py
```
*Expected Output*: "SUCCESS: All critical systems operational."

### 2. Dashboard Threat Simulation
Validates that the Machine Learning models generate correct classifications for simulated traffic vectors (Normal, SYN Flood, Port Scan, Brute Force), and that the dashboard maps these to the correct Threat Levels (SECURE, MODERATE, CRITICAL).
```bash
python scripts/test_dashboard_threats.py
```

### 3. Unit and Logic Testing
Test individual subsystems such as the heuristic rule engine, ML pipelines, and zero-day detectors:
- **Heuristic Rule Engine**: Verifies sliding-window logic and counter resets.
  ```bash
  python scripts/test_rule_logic.py
  ```
- **System Unit Tests**: Runs Python `unittest` suite for feature extraction structures.
  ```bash
  python scripts/verify_system.py
  ```
- **ML Specific Tests**: Validate `AnomalyDetector` responses with hardcoded NSL-KDD vectors (Normal vs. Neptune DoS).
  ```bash
  python scripts/verify_ml.py
  ```
- **Isolation Forest Live Test**: Manually debugs zero-day detection by simulating normal HTTP downloads vs. Port Scans and observing anomaly scores.
  ```bash
  python scripts/test_live_iforest.py
  ```
- **Quick Model Debugging**: A lightweight script to debug the Random Forest model quickly.
  ```bash
  python scripts/debug_model.py
  ```

---

## 🧠 Training & Evaluating Models

If you want to retrain the models from scratch using the provided NSL-KDD dataset, follow these steps from the root directory:

**1. Train the Supervised Model (Random Forest)**
This step generates `rf_model.pkl`, `scaler.pkl`, and `label_encoder.pkl` in the `models/` directory.
```bash
python scripts/train_supervised.py
```

**2. Train the Unsupervised Model (Isolation Forest)**
This step generates `iforest_model.pkl` in the `models/` directory. It uses the `scaler.pkl` generated in the previous step.
```bash
python scripts/train_model.py
```

**3. Evaluate the Models**
To check accuracy, precision, and recall against the `KDDTest+.txt` test set:
```bash
python scripts/evaluate_model.py      # Evaluates Random Forest
python scripts/evaluate_iforest.py    # Evaluates Isolation Forest
```

### 📊 Expected Performance
- **Accuracy**: Projected between 90.0% and 95.6% based on NSL-KDD benchmarks.
- **Efficiency**: Designed to be lightweight with real-time monitoring of CPU and RAM usage to ensure minimal system overhead.

---

## 🛡️ System Architecture & Flow

1. **Data Acquisition**: Raw binary frames are captured from the Network Interface Card (NIC) by `src/network_engine.py`.
2. **Preprocessing**: Packets are parsed, aggregated, and transformed into a 14-feature vector matching the NSL-KDD schema.
3. **Primary Inspection (Heuristics)**: `src/rule_engine.py` applies hard sliding-window thresholds to immediately flag overt, high-volume attacks (e.g., volumetric DDoS).
4. **Machine Learning Analysis**: `src/ml_engine.py` ingests the features.
   - The Random Forest classifies it against known attack vectors.
   - If unclassified by RF, the Isolation Forest checks the anomaly score ("path length") to detect novel, zero-day behaviors.
5. **Alerting**: The GUI (`src/gui_dashboard.py`) triggers visual threat level indicators (SECURE, MODERATE, CRITICAL) when thresholds are breached and logs incidents for review.

### Detailed Module Breakdown

#### 1. `src/main.py` (The Orchestrator)
This is the entry point that ties the system together. It initializes the multithreading environment, spawning the packet sniffer on a background thread and running the `CustomTkinter` GUI on the main thread. It manages the queue that passes threat alerts from the backend to the frontend seamlessly.

#### 2. `src/network_engine.py` (The Sniffer & Preprocessor)
Responsible for raw data acquisition. It utilizes the `scapy` library to sniff packets in promiscuous mode. As packets arrive, it:
- Extracts IP and TCP/UDP headers.
- Aggregates packet statistics over a rolling 2-second time window.
- Calculates derived features like `same_srv_rate`, `diff_srv_rate`, and `serror_rate` to construct a 14-dimensional feature vector exactly matching the structure the ML models were trained on.

#### 3. `src/rule_engine.py` (The First Line of Defense)
An extremely fast, heuristic-based logic engine. It maintains internal counters for IP addresses and ports to perform sliding-window analysis. 
- It can instantly detect **SYN Floods** (by counting incomplete handshakes), **Volume Floods/DDoS** (by tracking overall packets per second), and **Port Scans** (by tracking rapid connections to multiple distinct ports from a single source). It overrides the ML engine if it detects an overt, high-speed attack.

#### 4. `src/ml_engine.py` (The Brains)
The dual-stage machine learning engine:
- **Stage 1 (Supervised - Random Forest)**: Receives the 14-feature vector and scales it. The Random Forest checks for known attack signatures. It outputs a confidence score, and if the threat is recognized (e.g., Neptune DoS, Brute Force), it classifies the traffic.
- **Stage 2 (Unsupervised - Isolation Forest)**: If the Random Forest deems the traffic "normal", the Isolation Forest evaluates it for structural anomalies. By computing the "path length" of the data point, it flags packets that deviate significantly from established normal behaviors, alerting you to potential zero-day threats.

#### 5. `src/gui_dashboard.py` (The User Interface)
A modern, dark-themed dashboard built with `CustomTkinter`. It constantly polls system resources (CPU/RAM using `psutil`) and updates a live scrolling text log with network traffic. Crucially, it translates the output from `ml_engine.py` and `rule_engine.py` into human-readable **Threat Levels**:
- **SECURE** (Green): Normal, benign traffic.
- **MODERATE** (Yellow): Low-volume anomalies or slow port scans.
- **CRITICAL** (Red): Volumetric floods, active DoS attacks, or high-confidence malicious signatures.

---

##  **Screenshots**


<img width="548" height="245" alt="netguard1image" src="https://github.com/user-attachments/assets/2c14957e-e77b-49ef-bb2b-1c48517007b1" />

<img width="548" height="245" alt="netguard image 3" src="https://github.com/user-attachments/assets/b29b4ebb-628e-4ee2-bbb0-7d7f57d18254" />

<img width="548" height="245" alt="netguardimage2" src="https://github.com/user-attachments/assets/416d4b95-740a-4941-a911-7987798ad535" />
