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

**Machines deployment Guide**

 git clone https://github.com/GoVaish/GraylogProject

**Prereqs (Ubuntu 24.04).** 
 1) Install once
sudo apt update
sudo apt -y install tcpdump openjdk-8-jre-headless filebeat logstash curl jq

**Install env files, runners, and services**
 2) Env files → /etc/
sudo install -m 0644 system/env/tcpdump-cfm.env /etc/tcpdump-cfm.env
sudo install -m 0644 system/env/cfm-watch.env   /etc/cfm-watch.env

 3) Runner scripts → /usr/local/sbin
sudo install -m 0755 system/bin/tcpdump-cfm.sh /usr/local/sbin/tcpdump-cfm.sh
sudo install -m 0755 system/bin/cfm-watch.sh   /usr/local/sbin/cfm-watch.sh

4) Systemd units → /etc/systemd/system
sudo install -m 0644 system/systemd/tcpdump-cfm.service /etc/systemd/system/tcpdump-cfm.service
sudo install -m 0644 system/systemd/cfm-watch.service   /etc/systemd/system/cfm-watch.service

5) Prepare data paths
sudo mkdir -p /var/lib/tcpdump /var/log/cicflowmeter /var/log/traffic
sudo chown tcpdump:tcpdump /var/lib/tcpdump
sudo chmod 0750 /var/lib/tcpdump

6) Enable & start capture → features → shipping
sudo systemctl daemon-reload
sudo systemctl enable --now tcpdump-cfm.service
sudo systemctl enable --now cfm-watch.service

**Install Filebeat & Logstash pipeline**

7) Copy pipeline configs
sudo install -m 0644 log-pipeline/filebeat.yml /etc/filebeat/filebeat.yml
sudo install -m 0644 log-pipeline/logstash.conf /etc/logstash/conf.d/dns-ddos.conf

8) Optional: set output endpoints via systemd env (no config edits)
sudo mkdir -p /etc/systemd/system/logstash.service.d
sudo tee /etc/systemd/system/logstash.service.d/override.conf >/dev/null <<'EOF'
[Service]
Environment=GRAYLOG_HOST=192.168.56.6
Environment=GRAYLOG_PORT=12201
Environment=API_URL=http://192.168.56.10:8000/ingest
# Environment=API_KEY=your-secret-key   
 
9) Validate Logstash config, then restart both
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t -f /etc/logstash/conf.d/dns-ddos.conf
sudo systemctl daemon-reload
sudo systemctl restart logstash
sudo systemctl enable logstash
sudo systemctl restart filebeat
sudo systemctl enable filebeat

**Smoke Tests**

>> Watch pcap rotation
ls -ltr /var/lib/tcpdump | tail

>> Generate DNS traffic from any VM (replace <DNS-IP> as needed)
dig @<DNS-IP> example.com +short

>> Confirm CSVs appear
ls -ltr /var/log/cicflowmeter | tail

>> Check Logstash logs for HTTP output success
journalctl -u logstash -e --no-pager | tail -n 100

>> Independently test API (replace URL)
curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"ping":"ok","ts":"'"$(date -Iseconds)"'"}' \
  http://192.168.56.10:8000/ingest | jq .

>> Send a sample JSON line for the 'traffic' input
echo '{"event":"dns","qname":"example.com","src":"192.168.56.104"}' | sudo tee -a /var/log/traffic/test.json

>> Confirm Graylog input is running (UI → System → Inputs → GELF UDP 12201)

journalctl -u filebeat -e --no-pager | tail -n 100 (Check Filebeat logs)
journalctl -u logstash -e --no-pager | tail -n 100 (Check Logstash logs)
