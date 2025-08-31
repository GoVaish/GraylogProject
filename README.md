# 🛡️ Detecting DNS-DDoS Attacks with Machine Learning and Graylog Integration

Author: Vaishnavi Bhanudas Gobade

Degree:  MSc Cyber Security, University of Roehampton, London

## 📌 Project Overview

This project develops a real-time DNS Distributed Denial-of-Service (DDoS) detection and alerting system by combining Machine Learning (ML) with Graylog, an open-source SIEM (Security Information and Event Management) platform.

The system is designed to help Small and Medium Enterprises (SMEs) gain affordable and intuitive threat visibility.
Unlike traditional IDS tools (Snort, Suricata, Zeek) that rely on static signatures, this project leverages machine learning models to detect evolving attack patterns and integrates the results into Graylog dashboards for real-time monitoring and alerting.

## 🎯 Objectives

✅ Detect DNS-based DDoS attacks using supervised (Random Forest, SVM) and unsupervised (K-Means, Fuzzy C-Means) ML models.

✅ Integrate ML inference outputs with Graylog for visualization and alerting.

✅ Build customizable Graylog dashboards for technical SOC teams and non-technical decision makers.

✅ Simulate DDoS attack traffic in a controlled lab environment and evaluate detection effectiveness.

## 🛠️ Technology Stack
Component	Technology Used
OS/Environment	Ubuntu 24.04 LTS (VirtualBox VMs)
SIEM	Graylog 5.1
Databases	Elasticsearch 7.x, MongoDB 6.x
Log Forwarder	Filebeat → Logstash
ML Frameworks	Scikit-learn, XGBoost, Imbalanced-learn (SMOTE), Pandas, NumPy
Datasets	CIC-DNS2017, CAIDA, IEEE Public DNS DDoS datasets
⚙️ System Architecture

## Pipeline:

Source VM (DNS traffic)  
        ↓
CICFlowMeter (CSV feature extraction)  
        ↓
Filebeat → Logstash (CSV → JSON parsing)  
        ↓
Custom REST API (Feature preprocessing + ML inference)  
        ↓
Graylog 5 Dashboards (Monitoring + Alerting)


## 📌 High-level Diagram:
(Insert your architecture-diagram.png here once added in repo)

📊 Features & Detection

The ML models use flow-based and packet-level features:

Flow Statistics: Duration, Bytes/s, Packets/s, Inter-Arrival Times (IAT)

Packet Features: Min/Max/Mean packet length, variance, standard deviation

TCP Flags: SYN, ACK, PSH, URG counts

Traffic Ratios: Forward vs Backward packet/byte imbalance

## 🚨 Key Outcomes

Random Forest achieved near-perfect accuracy (≈ 99.99%) with very low false positives.

XGBoost delivered robust performance with higher recall, reducing missed attack detections.

Graylog Dashboards visualized traffic anomalies in real-time, providing actionable alerts within 2 seconds.

## 🚀 Getting Started

**Clone the Repository**

git clone https://github.com/<your-username>/dns-ddos-detection-graylog-ml.git
cd dns-ddos-detection-graylog-ml


**Set up Python environment**

python3 -m venv venv
source venv/bin/activate
pip install -r api/requirements.txt


**Configure Filebeat & Logstash**
Update filebeat.yml and logstash.conf with your server IPs and ports.
/etc/filebeat/filebeat.yml
/etc/logstash/conf.d/ddos.conf

**Run ML Inference API**

cd api
python app.py


**Import Graylog Dashboards**
Upload JSON from /graylog-dashboards/.
