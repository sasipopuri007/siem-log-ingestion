import os
import json

sample_dir = os.path.join(os.path.dirname(__file__), "sample_logs")
os.makedirs(sample_dir, exist_ok=True)

# 1. CSE-CIC-IDS2018 CSV Sample
ids2018_csv = """Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,Src IP,Dst IP,Label
80,6,2026-09-11 10:15:30,1250,5,4,172.31.66.83,10.0.0.5,Benign
443,6,2026-09-11 10:16:01,890,3,3,172.31.66.83,10.0.0.8,Benign
22,6,2026-09-11 10:17:45,4500,12,10,192.168.1.105,172.31.66.83,SSH-Bruteforce
8080,6,2026-09-11 10:18:12,320,1,1,10.0.0.12,172.31.66.83,Benign
"""
with open(os.path.join(sample_dir, "sample_ids2018.csv"), "w", encoding="utf-8") as f:
    f.write(ids2018_csv)

# 2. Syslog & auth.log Sample
syslog_txt = """<34>Sep 11 10:20:15 server01 sshd[14205]: Failed password for invalid user admin from 192.168.1.50 port 44892 ssh2
<34>Sep 11 10:20:18 server01 sshd[14205]: Failed password for invalid user admin from 192.168.1.50 port 44894 ssh2
<13>Sep 11 10:21:05 server01 sshd[14210]: Accepted password for root from 192.168.1.10 port 51200 ssh2
2026-09-11 10:22:00 | SERVER02 | 10.0.0.15 | dbadmin | DATABASE_LOGIN | SUCCESS
"""
with open(os.path.join(sample_dir, "sample_syslog.log"), "w", encoding="utf-8") as f:
    f.write(syslog_txt)

# 3. Snort Alert Sample
snort_txt = """[**] [1:1000001:2] ICMP Ping Detected [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.1.100 -> 192.168.1.1
[**] [1:2000002:1] ET SCAN Potential Nmap Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.1.50:44102 -> 192.168.1.1:80
"""
with open(os.path.join(sample_dir, "sample_snort.alert"), "w", encoding="utf-8") as f:
    f.write(snort_txt)

# 4. NDJSON Sample
ndjson_txt = """{"timestamp": "2026-09-11T10:30:00Z", "src_ip": "192.168.1.88", "dst_ip": "10.0.0.1", "user": "jdoe", "event_type": "UserLogin", "status": "SUCCESS", "severity": "LOW"}
{"timestamp": "2026-09-11T10:31:15Z", "src_ip": "192.168.1.200", "dst_ip": "10.0.0.1", "user": "root", "event_type": "SudoAccess", "status": "FAILED", "severity": "HIGH"}
"""
with open(os.path.join(sample_dir, "sample_jsonl.ndjson"), "w", encoding="utf-8") as f:
    f.write(ndjson_txt)

# 5. Key-Value Sample
kv_txt = """src_ip=192.168.1.12 dst_ip=10.0.0.50 user=operator action=FILE_ACCESS status=ALLOWED severity=INFO
src_ip=192.168.1.99 dst_ip=10.0.0.50 user=guest action=CONFIG_CHANGE status=DENIED severity=WARNING
"""
with open(os.path.join(sample_dir, "sample_kv.txt"), "w", encoding="utf-8") as f:
    f.write(kv_txt)

# 6. Malformed Log Sample
malformed_txt = """2026-09-11 11:00:00 | SERVER01 | 192.168.1.10 | admin | LOGIN | SUCCESS
--- CORRUPTED UNKNOWN UNSTRUCTURED LINE ---
2026-09-11 11:02:15 | SERVER01 | 192.168.1.15 | user1 | LOGOUT | SUCCESS
"""
with open(os.path.join(sample_dir, "sample_malformed.log"), "w", encoding="utf-8") as f:
    f.write(malformed_txt)

print("All sample logs written successfully!")
