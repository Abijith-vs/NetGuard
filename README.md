````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````# **NetGuard: Real-Time Network Anomaly Detection System using Machine Learning**




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

Efficiency: Designed to be lightweight with real-time monitoring of CPU and RAM usage to ensure minimal system overhead.