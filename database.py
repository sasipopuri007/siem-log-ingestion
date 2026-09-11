import os
import sqlite3
import json
from typing import List, Dict, Any, Optional, Tuple

# Dynamic Storage Path Resolution (Supports Local, Render /var/data, and Vercel Serverless /tmp)
def get_siem_data_dir() -> str:
    if "SIEM_DATA_DIR" in os.environ:
        target = os.environ["SIEM_DATA_DIR"]
    elif os.environ.get("VERCEL") == "1" or os.environ.get("VERCEL_ENV"):
        target = "/tmp/siem_data"
    else:
        target = os.path.dirname(__file__)

    try:
        os.makedirs(target, exist_ok=True)
    except Exception:
        target = "/tmp/siem_data"
        os.makedirs(target, exist_ok=True)

    return target

SIEM_DATA_DIR = get_siem_data_dir()
DB_PATH = os.environ.get("SIEM_DB_PATH", os.path.join(SIEM_DATA_DIR, "siem.db"))

def get_db_connection():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        try:
            os.makedirs(db_dir, exist_ok=True)
        except Exception:
            pass
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite database and creates security_logs table with indexes."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            organization TEXT,
            source TEXT,
            source_type TEXT,
            hostname TEXT,
            ip_address TEXT,
            destination_ip TEXT,
            source_port TEXT,
            destination_port TEXT,
            user TEXT,
            event_type TEXT,
            event_id TEXT,
            provider TEXT,
            protocol TEXT,
            status TEXT,
            action TEXT,
            severity TEXT,
            attack_type TEXT,
            suspicious TEXT,
            raw_log TEXT,
            raw_data TEXT,
            log_file TEXT,
            parser_status TEXT,
            parser_warning TEXT,
            fingerprint TEXT,
            is_duplicate INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Create performance indexes
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON security_logs(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_source ON security_logs(source);",
        "CREATE INDEX IF NOT EXISTS idx_source_type ON security_logs(source_type);",
        "CREATE INDEX IF NOT EXISTS idx_organization ON security_logs(organization);",
        "CREATE INDEX IF NOT EXISTS idx_ip_address ON security_logs(ip_address);",
        "CREATE INDEX IF NOT EXISTS idx_event_type ON security_logs(event_type);",
        "CREATE INDEX IF NOT EXISTS idx_severity ON security_logs(severity);",
        "CREATE INDEX IF NOT EXISTS idx_fingerprint ON security_logs(fingerprint);"
    ]
    for idx_sql in indexes:
        cursor.execute(idx_sql)

    conn.commit()
    conn.close()

def insert_batch(records: List[Dict[str, Any]]) -> Tuple[int, int]:
    """Inserts batch of normalized records into security_logs table, tracking duplicates."""
    if not records:
        return 0, 0

    conn = get_db_connection()
    cursor = conn.cursor()

    inserted_count = 0
    duplicate_count = 0

    # Get set of existing fingerprints for batch duplicate check
    fingerprints = [r.get("fingerprint") for r in records if r.get("fingerprint")]
    existing_fps = set()
    if fingerprints:
        for i in range(0, len(fingerprints), 500):
            chunk = fingerprints[i:i+500]
            placeholders = ",".join(["?"] * len(chunk))
            cursor.execute(f"SELECT fingerprint FROM security_logs WHERE fingerprint IN ({placeholders})", chunk)
            for row in cursor.fetchall():
                existing_fps.add(row["fingerprint"])

    insert_sql = """
        INSERT INTO security_logs (
            timestamp, organization, source, source_type, hostname, ip_address, destination_ip,
            source_port, destination_port, user, event_type, event_id, provider, protocol,
            status, action, severity, attack_type, suspicious, raw_log, raw_data, log_file,
            parser_status, parser_warning, fingerprint, is_duplicate
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    rows_to_insert = []
    for r in records:
        fp = r.get("fingerprint")
        is_dup = 1 if (fp and fp in existing_fps) else 0
        if is_dup:
            duplicate_count += 1
        
        rows_to_insert.append((
            r.get("timestamp"),
            r.get("organization") or "Default Org",
            r.get("source") or "Unknown Source",
            r.get("source_type") or "GENERIC",
            r.get("hostname"),
            r.get("ip_address"),
            r.get("destination_ip"),
            r.get("source_port"),
            r.get("destination_port"),
            r.get("user"),
            r.get("event_type"),
            r.get("event_id"),
            r.get("provider"),
            r.get("protocol"),
            r.get("status"),
            r.get("action"),
            r.get("severity"),
            r.get("attack_type"),  # ONLY source-provided
            r.get("suspicious"),   # ONLY source-provided
            r.get("raw_log"),
            r.get("raw_data"),
            r.get("log_file"),
            r.get("parser_status", "SUCCESS"),
            r.get("parser_warning"),
            fp,
            is_dup
        ))
        inserted_count += 1

    cursor.executemany(insert_sql, rows_to_insert)
    conn.commit()
    conn.close()

    return inserted_count, duplicate_count

def get_events(
    page: int = 1,
    per_page: int = 50,
    search: Optional[str] = None,
    organization: Optional[str] = None,
    source: Optional[str] = None,
    source_type: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    sort_by: str = "id",
    sort_order: str = "DESC"
) -> Tuple[List[Dict[str, Any]], int]:
    """Retrieves paginated and filtered events from security_logs table."""
    conn = get_db_connection()
    cursor = conn.cursor()

    conditions = []
    params = []

    if search:
        s_term = f"%{search}%"
        conditions.append(
            "(raw_log LIKE ? OR ip_address LIKE ? OR destination_ip LIKE ? OR user LIKE ? OR hostname LIKE ? OR event_type LIKE ?)"
        )
        params.extend([s_term] * 6)

    if organization:
        conditions.append("organization = ?")
        params.append(organization)

    if source:
        conditions.append("source = ?")
        params.append(source)

    if source_type:
        conditions.append("source_type = ?")
        params.append(source_type)

    if severity:
        conditions.append("severity = ?")
        params.append(severity)

    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)

    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

    # Count total
    count_sql = f"SELECT COUNT(*) as total FROM security_logs{where_clause}"
    cursor.execute(count_sql, params)
    total = cursor.fetchone()["total"]

    # Allowed sort columns
    allowed_sorts = ["id", "timestamp", "organization", "source", "source_type", "severity", "ip_address", "event_type"]
    sort_col = sort_by if sort_by in allowed_sorts else "id"
    order_dir = "DESC" if sort_order.upper() == "DESC" else "ASC"

    offset = (page - 1) * per_page
    query_sql = f"SELECT * FROM security_logs{where_clause} ORDER BY {sort_col} {order_dir} LIMIT ? OFFSET ?"
    cursor.execute(query_sql, params + [per_page, offset])

    rows = cursor.fetchall()
    events = [dict(row) for row in rows]
    conn.close()

    return events, total

def get_event_by_id(event_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_logs WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_stats() -> Dict[str, Any]:
    """Computes SIEM dashboard metrics and aggregation statistics."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as count FROM security_logs")
    total_events = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(DISTINCT source) as count FROM security_logs")
    total_sources = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(DISTINCT hostname) as count FROM security_logs WHERE hostname IS NOT NULL AND hostname != ''")
    total_systems = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(DISTINCT organization) as count FROM security_logs")
    total_orgs = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(DISTINCT log_file) as count FROM security_logs")
    files_processed = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM security_logs WHERE severity IN ('HIGH', 'CRITICAL')")
    high_severity_events = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM security_logs WHERE parser_status = 'PARSED_WITH_WARNINGS'")
    parser_warnings = cursor.fetchone()["count"]

    # Aggregations
    cursor.execute("SELECT source, COUNT(*) as count FROM security_logs GROUP BY source ORDER BY count DESC LIMIT 10")
    by_source = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT source_type, COUNT(*) as count FROM security_logs GROUP BY source_type ORDER BY count DESC")
    by_source_type = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT organization, COUNT(*) as count FROM security_logs GROUP BY organization ORDER BY count DESC")
    by_organization = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT severity, COUNT(*) as count FROM security_logs GROUP BY severity ORDER BY count DESC")
    by_severity = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT date(created_at) as date, COUNT(*) as count FROM security_logs GROUP BY date(created_at) ORDER BY date DESC LIMIT 14")
    timeline = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return {
        "total_events": total_events,
        "total_sources": total_sources,
        "total_systems": total_systems,
        "total_organizations": total_orgs,
        "files_processed": files_processed,
        "high_severity_events": high_severity_events,
        "parser_warnings": parser_warnings,
        "by_source": by_source,
        "by_source_type": by_source_type,
        "by_organization": by_organization,
        "by_severity": by_severity,
        "timeline": timeline
    }

def get_unique_sources() -> List[str]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT source FROM security_logs WHERE source IS NOT NULL ORDER BY source")
    rows = cursor.fetchall()
    conn.close()
    return [r["source"] for r in rows]

def get_unique_organizations() -> List[str]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT organization FROM security_logs WHERE organization IS NOT NULL ORDER BY organization")
    rows = cursor.fetchall()
    conn.close()
    return [r["organization"] for r in rows]
