import os
import uuid
import csv
import io
from flask import Flask, request, jsonify, render_template, send_file, Response
from werkzeug.utils import secure_filename

import database
from ingestion.pipeline import LogIngestionPipeline

app = Flask(__name__, template_folder="templates", static_folder="static")

# Production environment directory configuration (e.g. Render Persistent Disk /var/data)
BASE_DIR = os.path.dirname(__file__)
SIEM_DATA_DIR = os.environ.get("SIEM_DATA_DIR", BASE_DIR)
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(SIEM_DATA_DIR, "uploads"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", os.path.join(SIEM_DATA_DIR, "output"))

os.makedirs(SIEM_DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 100 MB Maximum File Upload Limit
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

# Initialize SIEM Database on startup (Persistent SQLite)
database.init_db()

# Production Health Check Endpoint
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

# Web Application UI Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/siem")
def siem_dashboard_page():
    return render_template("index.html")

@app.route("/events")
def events_page():
    return render_template("index.html")

@app.route("/ml-handoff")
def ml_handoff_page():
    return render_template("index.html")

# ==================== REST APIs ====================

@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file field provided in upload request."}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    orig_filename = secure_filename(file.filename) or "log_upload.log"
    unique_prefix = str(uuid.uuid4())[:8]
    stored_filename = f"{unique_prefix}_{orig_filename}"
    filepath = os.path.join(UPLOAD_DIR, stored_filename)

    try:
        file.save(filepath)
        return jsonify({
            "success": True,
            "filename": orig_filename,
            "stored_filename": stored_filename,
            "filepath": filepath,
            "size": os.path.getsize(filepath)
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to save upload file: {str(e)}"}), 500

@app.route("/api/process", methods=["POST"])
def api_process():
    data = request.get_json(silent=True) or {}
    filepath = data.get("filepath")
    filename = data.get("filename")

    if not filepath or not os.path.exists(filepath):
        stored = data.get("stored_filename")
        if stored:
            filepath = os.path.join(UPLOAD_DIR, stored)

    if not filepath or not os.path.exists(filepath):
        return jsonify({"error": "Uploaded log file path invalid or file missing on server."}), 400

    organization = data.get("organization") or "Organization 1"
    source = data.get("source") or filename or os.path.basename(filepath)

    try:
        result = LogIngestionPipeline.process_file(
            filepath=filepath,
            organization=organization,
            source=source
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

@app.route("/api/status/<job_id>", methods=["GET"])
def api_status(job_id):
    status = LogIngestionPipeline.get_job_status(job_id)
    if not status:
        return jsonify({"error": "Job ID not found"}), 404
    return jsonify(status), 200

@app.route("/api/events", methods=["GET"])
def api_events():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    search = request.args.get("search")
    organization = request.args.get("organization")
    source = request.args.get("source")
    source_type = request.args.get("source_type")
    severity = request.args.get("severity")
    event_type = request.args.get("event_type")
    sort_by = request.args.get("sort_by", "id")
    sort_order = request.args.get("sort_order", "DESC")

    try:
        events, total = database.get_events(
            page=page,
            per_page=per_page,
            search=search,
            organization=organization,
            source=source,
            source_type=source_type,
            severity=severity,
            event_type=event_type,
            sort_by=sort_by,
            sort_order=sort_order
        )
        return jsonify({
            "events": events,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page if total > 0 else 1
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch SIEM events: {str(e)}"}), 500

@app.route("/api/events/<int:event_id>", methods=["GET"])
def api_event_detail(event_id):
    event = database.get_event_by_id(event_id)
    if not event:
        return jsonify({"error": "Event ID not found"}), 404
    return jsonify(event), 200

@app.route("/api/stats", methods=["GET"])
def api_stats():
    try:
        stats = database.get_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": f"Failed to calculate SIEM metrics: {str(e)}"}), 500

@app.route("/api/sources", methods=["GET"])
def api_sources():
    sources = database.get_unique_sources()
    return jsonify({"sources": sources}), 200

@app.route("/api/organizations", methods=["GET"])
def api_organizations():
    orgs = database.get_unique_organizations()
    return jsonify({"organizations": orgs}), 200

@app.route("/api/export", methods=["GET"])
def api_export():
    """Exports normalized SIEM schema records into CSV format for ML module handoff."""
    try:
        events, _ = database.get_events(page=1, per_page=100000)

        output = io.StringIO()
        fieldnames = [
            "id", "timestamp", "organization", "source", "source_type",
            "hostname", "ip_address", "destination_ip", "source_port", "destination_port",
            "user", "event_type", "event_id", "provider", "protocol",
            "status", "action", "severity", "attack_type", "suspicious", "created_at"
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for ev in events:
            writer.writerow(ev)

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=normalized_siem_ml_handoff.csv"}
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate CSV export: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
