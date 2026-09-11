import os
import json
import re
from typing import Tuple

class FormatDetector:
    """Detects security log formats based on extension, magic bytes, and content sniffing."""

    @staticmethod
    def detect(filepath: str) -> str:
        if not os.path.exists(filepath):
            return "GENERIC_TEXT"

        ext = os.path.splitext(filepath)[1].lower()

        # 1. EVTX Check (Extension or Magic Bytes ElfFile\x00)
        if ext == ".evtx":
            return "EVTX"
        try:
            with open(filepath, "rb") as f:
                header = f.read(8)
                if header == b"ElfFile\x00":
                    return "EVTX"
        except Exception:
            pass

        # Read sample text lines safely for content sniffing
        lines = []
        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
        for enc in encodings:
            try:
                with open(filepath, "r", encoding=enc, errors="ignore") as f:
                    for _ in range(30):
                        line = f.readline()
                        if not line:
                            break
                        lines.append(line)
                if lines:
                    break
            except Exception:
                continue

        sample_text = "".join(lines)
        if not sample_text.strip() or not lines:
            return "GENERIC_TEXT"

        # 2. Snort Alert Check
        if "[**] [" in sample_text or ext in [".alert", ".snort"]:
            return "SNORT"

        # 3. CSV Check (Extension or Header Comma/Tab inspection)
        if ext == ".csv":
            return "CSV"

        if len(lines) > 0 and ("," in lines[0] or "\t" in lines[0]):
            first_line = lines[0]
            delimiters = [",", "\t", ";"]
            for sep in delimiters:
                parts = first_line.split(sep)
                if len(parts) >= 2:
                    common_headers = [
                        "timestamp", "time", "date", "src_ip", "source_ip", "dst_ip",
                        "dest_ip", "protocol", "port", "user", "username", "status",
                        "action", "severity", "label", "attack", "class", "flow duration"
                    ]
                    parts_lower = [p.strip().lower() for p in parts]
                    if any(h in parts_lower for h in common_headers):
                        return "CSV"

        # 4. JSON / NDJSON Check
        trimmed = sample_text.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                json.loads(sample_text)
                return "JSON"
            except Exception:
                pass

        if ext in [".ndjson", ".jsonl"] or (len(lines) > 0 and lines[0].strip().startswith("{") and lines[0].strip().endswith("}")):
            valid_json_count = 0
            for l in lines[:5]:
                try:
                    if l.strip():
                        json.loads(l.strip())
                        valid_json_count += 1
                except Exception:
                    break
            if valid_json_count >= max(1, len([l for l in lines[:5] if l.strip()])):
                return "NDJSON"

        # 5. Syslog / Auth Log Check
        syslog_pattern = re.compile(r"<\d+>|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}")
        if syslog_pattern.search(sample_text) and ("sshd" in sample_text or "kernel" in sample_text or "syslog" in sample_text or ext in [".syslog", ".log"]):
            return "SYSLOG"

        # 6. Fallback
        return "GENERIC_TEXT"
