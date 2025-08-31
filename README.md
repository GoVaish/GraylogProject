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
  http://<HOST_IP>:8000/ingest | jq .

>> Send a sample JSON line for the 'traffic' input
echo '{"event":"dns","qname":"example.com","src":"192.168.56.104"}' | sudo tee -a /var/log/traffic/test.json

>> Confirm Graylog input is running (UI → System → Inputs → GELF UDP 12201)

journalctl -u filebeat -e --no-pager | tail -n 100 (Check Filebeat logs)
journalctl -u logstash -e --no-pager | tail -n 100 (Check Logstash logs)


# 🧩 Challenges Faced & Fixes 

1) Graylog “not listening on IPv4” / no messages on 12201

Symptoms: GELF/UDP input created, but no messages; ss -lntu showed IPv6 or no bind; dashboards stayed empty.
Root cause: Default JVM/stack preferred IPv6 and/or Graylog input not bound to the correct interface.
Fixes:

Bound GELF/UDP input to the host-only/bridged IPv4 address (not just ::).

Forced IPv4 preference for the JVM running Graylog:

sudo systemctl edit graylog-server
[Service]
Environment="JAVA_OPTS=-Djava.net.preferIPv4Stack=true -Djava.net.preferIPv4Addresses=true"
sudo systemctl daemon-reload && sudo systemctl restart graylog-server


Verified path end-to-end:

ss -lup | grep 12201
**In Graylog UI: System → Inputs → GELF UDP → Started**

2) Logstash bind ambiguity (IPv4/IPv6)

Symptoms: Filebeat connected intermittently; beats input appeared on IPv6 only.
Fix: Explicit IPv4 binding in the beats input:

input { beats { port => 5044 host => "0.0.0.0" } }


Then:

sudo systemctl restart logstash && ss -lntup | grep 5044

3) “Text fields are not optimised for aggregations” in Graylog/Elasticsearch

Symptoms: Widget errors during aggregations/sorting on text fields.
Root cause: Elasticsearch 7 defaults string fields to text (no doc values).
Fixes (choose one):

Use keyword subfields in queries/aggregations (e.g., field.keyword in widget config).

Or, add a custom mapping in Graylog Index Set to define frequently-aggregated fields as keyword.

Avoid fielddata=true on text (memory-heavy).

4) CICFlowMeter produced no CSVs

Symptoms: Command returned without error but no files in /var/log/cicflowmeter.
Root causes: (a) Wrong Java version; (b) missing native libs / log directory; (c) PCAP link type.
Fixes:

Standardised on Java 8:

sudo apt -y install openjdk-8-jre-headless
sudo update-alternatives --config java   # select a Java 8 path


Ensured app log dir exists and readable:

sudo mkdir -p /opt/CICFlowMeter/build/install/CICFlowMeter/logs


Passed log4j property to reduce silent failures (wired in cfm-watch.sh):

-Dlog4j.configuration=file:/opt/cicflowmeter/log4j.properties


Captured Ethernet (EN10MB) frames by switching tcpdump from any (SLL2) to a real NIC (e.g., enp0s8) in /etc/tcpdump-cfm.env.

5) LINUX_SLL2 link type in PCAPs

Symptoms: PCAPs opened as SLL2; some tools (older builds) behaved inconsistently.
Fix: Set IFACE=enp0s8 (or your bridged adapter) instead of any in tcpdump-cfm.env, then:

sudo systemctl restart tcpdump-cfm

6) Systemd edits “not taking effect”

Symptoms: Changes via systemctl edit … didn’t apply.
Fix: Confirmed drop-in directory, then reloaded daemons:

sudo systemctl daemon-reload
sudo systemctl restart <service>
systemctl cat <service>   # verify active unit + drop-ins

7) CSV header handling in Logstash

Symptoms: Fields misaligned or empty; autodetect_column_names unsupported on some plugin versions.
Fixes:

Pinned a deterministic columns => [...] list for the CICFlowMeter 2019 schema when needed.

(Optional) Set pipeline.workers: 1 only if header inference and file concurrency caused race conditions; otherwise kept defaults.

8) File ownership & capabilities for tcpdump

Symptoms: Service failed to write into /var/lib/tcpdump.
Fixes:

sudo chown tcpdump:tcpdump /var/lib/tcpdump
sudo chmod 0750 /var/lib/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

9) “Command not found” / wrong paths in units

Symptoms: Units failed on boot; ExecStart couldn’t find binaries.
Fix: Used absolute paths (/usr/sbin/tcpdump, /usr/local/sbin/*.sh) and install(1) to deploy scripts with correct modes.

10) Generating test DNS traffic across VMs

Symptoms: No flows observed even though services were “running”.
Fixes:

**From a client VM:**
dig @<dns-server-ip> example.com +short
**Or generate load:**
for i in {1..200}; do dig @<dns-server-ip> example.com +nocookie +time=1 +tries=1 >/dev/null; done


Ensured both VMs are on the same host-only/bridged network and that port 53 is open.

⚠️ Known Issues & Workarounds

GELF message truncation on very large events: keep payloads lean (we remove bulky fields in Logstash), or switch to TCP GELF if needed.

Clock skew between VMs can skew timelines: enable systemd-timesyncd or chrony.

Elasticsearch back-pressure under load: tune index refresh, bulk_max_size in Filebeat, and JVM heap for Logstash/ES.

CSV schema drift across CICFlowMeter builds: pin columns => [...] to your exact header; store the header as an artifact in the repo.

# ✅ Reliability Hardening (What We Changed)

Two independent queues: pcaps → CSV (disk) and events → Logstash (beats), so brief outages don’t drop data.

Idempotent processing: .done markers in cfm-watch prevent double-ingest on restarts.

Retrying HTTP output: Logstash http output uses automatic retries and keep-alive to the ML API.

Explicit IPv4 everywhere: avoids dual-stack surprises in lab networks.

Interface pinning: enp0s8 (host-only/bridged) to get EN10MB frames consistently.

🧪 Quick Health Checklist
**Listeners**
ss -lntup | grep -E ':(5044|12201)\b'

**Capture & features**
ls -ltr /var/lib/tcpdump | tail
ls -ltr /var/log/cicflowmeter | tail

**Service logs**
journalctl -u tcpdump-cfm -e --no-pager | tail
journalctl -u cfm-watch   -e --no-pager | tail
journalctl -u filebeat    -e --no-pager | tail
journalctl -u logstash    -e --no-pager | tail
