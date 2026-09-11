# AI-Enhanced Automated Incident Response in SIEM: Log Ingestion System

A generic, high-performance, fault-tolerant web-based SIEM Log Ingestion System with SOC Analyst Support & Machine Learning Handoff.

---

## 📌 Implementation Scope & Boundary

This application implements the complete **Log Ingestion & SIEM Pipeline** up to **ML Handoff Ready**:

```
Multiple Systems / Organizations
              │
              ▼
        LOG COLLECTOR
              │
              ▼
       FORMAT DETECTION (EVTX, CSV, JSON, NDJSON, Syslog, Snort, Generic Text)
              │
              ▼
    SPECIALIZED / FALLBACK PARSER
              │
              ▼
        NORMALIZATION (Standardizes Timestamps, Severities, SHA-256 Fingerprints)
              │
              ▼
     VALIDATION / CLEANING
              │
              ▼
       SIEM DATABASE (siem.db Persistent SQLite)
              │
     SIEM SEARCH / STATISTICS
              │
              ▼
       ML-READY EXPORT (CSV Export for downstream Random Forest Models)
              │
              ▼
             STOP
```

> [!IMPORTANT]
> **Strict Team Boundary**: This module does **NOT** implement Random Forest models, attack predictions, XAI, Adaptive XAI, or automated response blocking actions. Downstream teammates will connect their machine learning classification modules directly to the exported ML-ready dataset.

---

## 🚀 Key Architectural Features

1. **Generic Log Format Support**:
   - **Windows EVTX**: Native parsing via `python-evtx` and XML ElementTree, extracting EventID, Hostname, Provider, Level, EventData IPs/users, and raw XML.
   - **Dynamic CSV**: Dynamic header auto-mapping for aliases (`timestamp`, `src_ip`, `dst_ip`, `user`, `protocol`, `severity`, `label`). Preserves original dataset labels (e.g. CSE-CIC-IDS2018).
   - **JSON / NDJSON**: Supports single objects, array payloads, and line-delimited NDJSON logs with key flattening.
   - **Syslog / auth.log**: Supports RFC3164, RFC5424, Linux `auth.log`, pipe-delimited text, and Key-Value (`src_ip=... dst_ip=...`) formats.
   - **Snort IDS Alerts**: Extracts SID, rule revision, message, protocol `{ICMP}`, source IP/port, and destination IP/port.
   - **Generic Fallback Parser**: RegEx & heuristic extraction for IPv4/IPv6, timestamps, usernames, ports, protocols, severities, keywords. Ensures **no non-empty log line is lost**.

2. **Fault Tolerance ("One Bad Record Never Crashes the SIEM")**:
   - Multi-encoding fallback decoder (`utf-8`, `utf-8-sig`, `latin-1`, `cp1252` with `errors='replace'`).
   - Per-record exception isolation: Malformed individual records log warnings without stopping the processing pipeline or crashing the web app.
   - User-friendly UI status display ("Processing completed with warnings"). No Python tracebacks exposed to users.

3. **Centralized SQLite SIEM Storage**:
   - Continuous append ingestion: New file uploads add records to the centralized `security_logs` table (never drops old database tables).
   - Performance indexing on `timestamp`, `source`, `source_type`, `organization`, `ip_address`, `severity`.
   - Event SHA-256 fingerprinting for duplicate detection (`is_duplicate`).

4. **Source Label Policy**:
   - Preserves source-provided labels (e.g. CSV `Label = SSH-Bruteforce` or Snort classification) inside `attack_type` or `raw_data`.
   - Never invents or predicts attack labels if absent (`attack_type = NULL`, `suspicious = NULL`).

---

## 🛠️ Local Installation & Setup

1. **Prerequisites**: Python 3.9+ installed.
2. **Install Dependencies**:
   ```bash
   cd siem_log_ingestion
   pip install -r requirements.txt
   ```
3. **Run Web Application**:
   ```bash
   python app.py
   ```
4. **Access UI & Health Endpoint**:
   - Web App UI: `http://localhost:5000`
   - Health Check: `http://localhost:5000/health` (Returns `{"status": "ok"}`)

---

## ⚡ VERCEL DEMO DEPLOYMENT

Follow these steps to deploy this application on Vercel for public college demonstration:

1. **Push Project to GitHub**:
   Ensure your project is committed and pushed to GitHub:
   ```bash
   git add .
   git commit -m "Add Vercel deployment configuration"
   git push -u origin main
   ```

2. **Deploy on Vercel**:
   - Go to your [Vercel Dashboard](https://vercel.com/dashboard).
   - Click **Add New...** $\rightarrow$ **Project**.
   - Import your GitHub repository (`siem-log-ingestion`).
   - Select the project root.
   - Vercel automatically detects the Python runtime (`api/index.py` & `vercel.json`).
   - Click **Deploy**.
   - Vercel will generate your public HTTPS URL automatically (e.g., `https://siem-log-ingestion.vercel.app`).

> [!WARNING]
> **Serverless Demonstration Storage Notice**:
> Vercel deployment is configured specifically for **public demonstration**.
> Vercel operates on a serverless architecture where local uploaded files and SQLite databases in `/tmp` are **ephemeral** (they persist during the active function instance but may reset on cold starts).
> For permanent production persistence, use a persistent disk provider (such as Render with `/var/data`) or an external database (such as PostgreSQL/Supabase).

---

## 🌐 PERMANENT RENDER DEPLOYMENT

For permanent storage hosting with a persistent disk mount (`/var/data`):

1. Connect GitHub repository to Render Web Service.
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `gunicorn app:app`
4. Health Check Path: `/health`
5. Mount Persistent Disk: `/var/data` (set `SIEM_DATA_DIR=/var/data`).

---

## 🧪 Running Automated Tests

Run the comprehensive unit test suite covering all required scenarios:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 🎬 14-Step Demonstration Guide

Follow these steps to demonstrate the complete end-to-end ingestion system:

1. **Start System**: Run `python app.py` in your terminal.
2. **Open Web UI**: Open `http://localhost:5000` in your browser.
3. **Upload Log 1 (CSE-CIC-IDS2018 / CSV)**:
   - Select **Organization 1 (Enterprise HQ)**.
   - Drag & drop or select `sample_logs/sample_ids2018.csv`.
4. **Process Log**: Click `[ PROCESS LOG ]`.
5. **Observe Stepper**: Watch the real-time pipeline stepper progress:
   `Upload → Format Detection (CSV) → Collection → Parsing → Normalization → Validation → SIEM Storage → ML Handoff Ready`.
6. **Verify Ingestion Summary**: Check events received, parsed, normalized, stored, and status `SUCCESS`.
7. **Open SIEM Events Explorer**: Click **Event Explorer** tab.
8. **Inspect Normalized Records**: Filter by Organization 1 or CSV source type; click `🔍 View` on an event to inspect normalized schema fields, raw log string, and raw JSON payload.
9. **Upload Log 2 (Different System & Organization)**:
   - Go back to **Ingestion Engine** tab.
   - Select **Organization 2 (Branch Office)**.
   - Select `sample_logs/sample_syslog.log` (Linux Syslog).
10. **Process & Verify Centralized SIEM**: Click `[ PROCESS LOG ]`. Navigate to **Event Explorer** or **SIEM Dashboard** to confirm that both Organization 1 and Organization 2 records coexist in the centralized database.
11. **Upload Log 3 (Snort IDS / Malformed Log)**:
    - Select `sample_logs/sample_snort.alert` or `sample_malformed.log`.
12. **Verify Fault Tolerance**: Click `[ PROCESS LOG ]`. Notice that the application processes all records cleanly, displays warnings count, and status `"Processing completed with warnings"` without crashing.
13. **Open ML Handoff Section**: Click the **ML Handoff** tab.
14. **Export ML-Ready Data**: Click `[ EXPORT ML-READY DATA ]` to download `normalized_siem_ml_handoff.csv` containing all standardized SIEM records ready for downstream machine learning consumption.
