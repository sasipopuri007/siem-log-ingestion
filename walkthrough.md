# Walkthrough - SIEM Log Ingestion System (Vercel & Render Deployment Ready)

The **Generic & Robust SIEM Log Ingestion System** under `C:\Users\user\.gemini\antigravity\scratch\siem_log_ingestion` is now fully configured for **Vercel Demo Deployment** as well as **Render Permanent Deployment**.

---

## ⚡ Vercel Demonstration Deployment Changes

1. **Native Python Serverless Entrypoint (`api/index.py`)**:
   - Created Vercel serverless function entrypoint exposing the top-level `app` Flask instance:
     ```python
     import sys, os
     sys.path.append(os.path.dirname(os.path.dirname(__file__)))
     from app import app
     ```

2. **Vercel Zero-Config Specification (`vercel.json`)**:
   - Created Vercel build and route specification directing all incoming traffic to `api/index.py` using Vercel's native `@vercel/python` runtime.

3. **Dynamic Serverless Storage (`/tmp` Fallback)**:
   - Refactored `database.py` and `app.py` path resolution:
     - On local machine / Render: uses standard persistent disk directories.
     - On Vercel: dynamically detects Vercel serverless environment (`VERCEL=1`) or unwritable root and routes temporary SQLite DB (`siem.db`), uploads, and exports to `/tmp/siem_data`.

4. **Preserved SIEM Ingestion Engine & Standard Features**:
   - Native EVTX (`python-evtx`), CSV, JSON, NDJSON, Syslog, auth.log, Snort, Key-Value, and Generic Text Fallback parsers remain 100% active.
   - Zero invented `attack_type` or `suspicious` values (strict ML team handoff boundary preserved).

5. **Health Check Endpoint (`GET /health`)**:
   - Returns `{"status": "ok"}` with HTTP 200.

---

## 🧪 Verification & Test Results

### 1. Automated Unit Test Suite
```bash
python -m unittest discover -s tests -p "test_*.py"
............
----------------------------------------------------------------------
Ran 12 tests in 0.960s

OK
```

### 2. Local Health Endpoint Verification
```bash
GET http://localhost:5000/health
HTTP 200 OK
{
  "status": "ok"
}
```

---

## 📁 Updated Codebase Structure

Target Location: `C:\Users\user\.gemini\antigravity\scratch\siem_log_ingestion`

```
siem_log_ingestion/
├── api/
│   └── index.py               # Vercel serverless Python entrypoint
├── vercel.json                # Vercel deployment routing configuration
├── render.yaml                # Render Blueprint deployment configuration
├── app.py                     # Production Flask Web Server & GET /health API
├── database.py                # SQLite SIEM Database management with Vercel /tmp support
├── requirements.txt           # Production dependencies (Flask, python-evtx, hexdump, gunicorn)
├── .gitignore                 # Version control exclusions
├── README.md                  # Comprehensive Documentation & Vercel/Render Setup Guide
├── generate_samples.py        # Helper script to create test security log files
├── ingestion/                 # Log sniffer, normalizer, and parser suite
├── static/                    # Dark-mode SOC UI CSS & JS
├── templates/                 # index.html
├── tests/                     # Unit test suite
└── sample_logs/               # Sample log files
```

---

## 🌐 How to Deploy on Vercel (5-Step Demonstration Guide)

1. **Stage and Commit Changes**:
   ```bash
   cd C:\Users\user\.gemini\antigravity\scratch\siem_log_ingestion
   git add .
   git commit -m "Add Vercel deployment configuration"
   git push -u origin main
   ```
2. **Open Vercel Dashboard**: Go to [https://vercel.com/dashboard](https://vercel.com/dashboard).
3. **Import GitHub Repository**: Click **Add New...** $\rightarrow$ **Project** $\rightarrow$ Select `siem-log-ingestion`.
4. **Deploy**: Vercel automatically detects the Python runtime (`api/index.py` & `vercel.json`). Click **Deploy**.
5. **Access Public Demo URL**: Vercel will generate your live HTTPS URL (e.g. `https://siem-log-ingestion.vercel.app`).
