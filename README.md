# Detecting DNS-DDoS Attacks with Machine Learning and Graylog Integration  

**Author:** Vaishnavi Bhanudas Gobade  
**Degree:** MSc Cyber Security, University of Roehampton, London. 
 
---

## 📌 Project Overview  

This project develops a **real-time DNS Distributed Denial-of-Service (DDoS) detection and alerting system** by combining **Machine Learning (ML)** with **Graylog**, an open-source Security Information and Event Management (SIEM) tool.  

The system is designed to help **Small and Medium Enterprises (SMEs)** gain intuitive and affordable threat visibility. Unlike traditional intrusion detection tools (Snort, Suricata, Zeek) that rely on static signatures, this project leverages ML to detect evolving attack patterns and integrates the results into Graylog dashboards for real-time monitoring and alerting.  

---

## 🎯 Objectives  

- Detect DNS-based DDoS attacks using supervised (Random Forest, SVM) and unsupervised (K-Means, Fuzzy C-Means) ML models.  
- Integrate ML outputs with Graylog to visualize and alert on anomalies in DNS traffic.  
- Build customizable Graylog dashboards for both technical and non-technical users.  
- Simulate DDoS attacks in a controlled lab environment to evaluate detection effectiveness.  

---

## 🛠️ Technology Stack  

- **OS/Environment:** Ubuntu 24.04 (VM, VirtualBox)  
- **SIEM Tool:** Graylog 5.1  
- **Databases:** Elasticsearch 7.x, MongoDB 6.x  
- **Log Forwarder:** Filebeat → Logstash  
- **ML Frameworks:** Scikit-learn, XGBoost, Imbalanced-learn (SMOTE), Pandas, NumPy  
- **Dataset:** CIC-DNS2017, CAIDA, and IEEE public datasets  

---

## ⚙️ System Architecture  

**Pipeline:**  

`Source VM (DNS traffic) → CICFlowMeter (CSV) → Filebeat → Logstash (CSV→JSON) → REST API (feature extraction + ML inference) → Graylog (Dashboards + Alerts)`  

<img width="1200" height="400" alt="Blank_diagram 1" src="https://github.com/user-attachments/assets/c6b41f59-45ef-47f5-bdc1-c4386e9a7ee7" />


---

## 📊 Features & Detection  

The ML model uses key traffic features such as:  

- **Flow Statistics:** Duration, Bytes/s, Packets/s, IAT (Inter-Arrival Times)  
- **Packet Features:** Min/Max/Mean packet length, variance, std deviation  
- **TCP Flags:** SYN, ACK, PSH, URG counts  
- **Request/Response Ratios:** Fwd vs Bwd traffic imbalance  

---
