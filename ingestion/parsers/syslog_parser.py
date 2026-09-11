import os
import re
from typing import Generator, Optional, Dict, Any
from .base import BaseParser, ParsedRecord
from .csv_parser import ALIAS_MAP

# Regex patterns for Syslog
RFC3164_PATTERN = re.compile(
    r"^(?:<(?P<pri>\d+)>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\.\-]+)\s+(?P<process>[\w\.\-\/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

RFC5424_PATTERN = re.compile(
    r"^(?:<(?P<pri>\d+)>)?1\s+(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[\+\-]\d{2}:\d{2})?)\s+(?P<hostname>[\w\.\-]+)\s+(?P<app_name>[\w\.\-]+)\s+(?P<proc_id>[\w\.\-]+)\s+(?P<msg_id>[\w\.\-]+)\s+(?P<sd>.*?)\s+(?P<message>.*)$"
)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KV_PATTERN = re.compile(r"(\b[\w_\-]+)=(?:\"([^\"]*)\"|'([^']*)'|(\S+))")

class SyslogParser(BaseParser):
    """Parses RFC3164/5424 Syslog, Linux auth.log, Pipe-delimited, and Key-Value log files."""

    def parse_file(
        self, filepath: str, organization: Optional[str] = None, source: Optional[str] = None
    ) -> Generator[ParsedRecord, None, None]:
        filename = os.path.basename(filepath)
        source_name = source or filename

        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
        lines = []
        for enc in encodings:
            try:
                with open(filepath, "r", encoding=enc, errors="replace") as f:
                    lines = f.readlines()
                if lines:
                    break
            except Exception:
                continue

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                ts, host, proc, msg = None, None, None, line_str
                pri = None
                kv_dict = {}

                # 1. Check RFC5424
                m5424 = RFC5424_PATTERN.match(line_str)
                if m5424:
                    gd = m5424.groupdict()
                    ts = gd.get("timestamp")
                    host = gd.get("hostname")
                    proc = gd.get("app_name")
                    msg = gd.get("message", "")
                    pri = gd.get("pri")
                else:
                    # 2. Check RFC3164
                    m3164 = RFC3164_PATTERN.match(line_str)
                    if m3164:
                        gd = m3164.groupdict()
                        ts = gd.get("timestamp")
                        host = gd.get("hostname")
                        proc = gd.get("process")
                        msg = gd.get("message", "")
                        pri = gd.get("pri")

                # Extract Key-Value pairs from message if present
                for match in KV_PATTERN.finditer(msg):
                    k = match.group(1).lower().replace("-", "_")
                    v = match.group(2) or match.group(3) or match.group(4)
                    kv_dict[k] = v

                # Also extract IP addresses from message
                ips = IP_PATTERN.findall(line_str)
                src_ip = kv_dict.get("src_ip") or kv_dict.get("source_ip") or kv_dict.get("src") or (ips[0] if ips else None)
                dst_ip = kv_dict.get("dst_ip") or kv_dict.get("dest_ip") or kv_dict.get("dst") or (ips[1] if len(ips) > 1 else None)

                # Extract user
                user = kv_dict.get("user") or kv_dict.get("username") or kv_dict.get("account") or None
                if not user:
                    user_m = re.search(r"for\s+(invalid\s+user\s+)?([\w\.\-]+)\s+from", msg, re.IGNORECASE)
                    if user_m:
                        user = user_m.group(2)

                # Extract action / event_type
                action = kv_dict.get("action") or None
                if not action:
                    if "Failed password" in msg or "authentication failure" in msg:
                        action = "LOGIN_FAILED"
                    elif "Accepted password" in msg or "session opened" in msg:
                        action = "LOGIN_SUCCESS"
                    elif "Invalid user" in msg:
                        action = "INVALID_USER"

                # Extract severity from PRI if available
                severity = None
                if pri is not None:
                    try:
                        severity_num = int(pri) % 8
                        sev_map = {0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "HIGH", 4: "MEDIUM", 5: "LOW", 6: "INFO", 7: "DEBUG"}
                        severity = sev_map.get(severity_num, "INFO")
                    except Exception:
                        pass
                if not severity and "severity" in kv_dict:
                    severity = kv_dict["severity"].upper()

                # Check pipe-delimited pattern
                if "|" in line_str and not m3164 and not m5424:
                    parts = [p.strip() for p in line_str.split("|")]
                    if len(parts) >= 4:
                        ts = ts or parts[0]
                        host = host or parts[1]
                        if IP_PATTERN.match(parts[2]):
                            src_ip = parts[2]
                        user = user or parts[3]
                        if len(parts) >= 5:
                            action = action or parts[4]

                # Determine if line matched structured syslog or requires warning
                is_structured = bool(m3164 or m5424 or (kv_dict and len(kv_dict) > 0) or ("|" in line_str and len(line_str.split("|")) >= 4))
                parser_status = "SUCCESS" if is_structured else "PARSED_WITH_WARNINGS"
                parser_warning = None if is_structured else "Unstructured line parsed as generic syslog event."

                parsed = ParsedRecord(
                    timestamp=ts,
                    organization=organization,
                    source=source_name,
                    source_type="SYSLOG",
                    hostname=host,
                    ip_address=src_ip,
                    destination_ip=dst_ip,
                    source_port=kv_dict.get("src_port") or kv_dict.get("source_port"),
                    destination_port=kv_dict.get("dst_port") or kv_dict.get("dest_port"),
                    user=user,
                    event_type=proc or "Syslog Event",
                    provider=proc,
                    protocol=kv_dict.get("proto") or kv_dict.get("protocol") or "Syslog",
                    status="FAILED" if "failed" in msg.lower() or "failure" in msg.lower() else "SUCCESS",
                    action=action,
                    severity=severity,
                    attack_type=kv_dict.get("attack_type") or kv_dict.get("attack"), # Preserved ONLY if present in KV
                    suspicious=kv_dict.get("suspicious"),                            # Preserved ONLY if present in KV
                    raw_log=line_str,
                    raw_data=kv_dict if kv_dict else {"message": msg},
                    log_file=filename,
                    parser_status=parser_status,
                    parser_warning=parser_warning
                )
                yield parsed

            except Exception as line_err:
                yield ParsedRecord(
                    organization=organization,
                    source=source_name,
                    source_type="SYSLOG",
                    raw_log=line_str,
                    log_file=filename,
                    parser_status="PARSED_WITH_WARNINGS",
                    parser_warning=f"Malformed syslog line #{idx}: {str(line_err)}"
                )
