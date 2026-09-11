import os
import csv
import json
from typing import Generator, Optional, Dict, Any
from .base import BaseParser, ParsedRecord

ALIAS_MAP = {
    "timestamp": ["timestamp", "time", "date", "datetime", "time_stamp", "ts"],
    "ip_address": ["src_ip", "source_ip", "srcip", "source", "client_ip", "ip_address", "ip", "src"],
    "destination_ip": ["dst_ip", "destination_ip", "dstip", "dest_ip", "server_ip", "dst", "target_ip"],
    "source_port": ["src_port", "source_port", "srcport", "s_port"],
    "destination_port": ["dst_port", "destination_port", "destport", "d_port"],
    "user": ["user", "username", "account", "account_name", "user_id"],
    "hostname": ["hostname", "host", "computer", "system_name", "machine_name"],
    "protocol": ["protocol", "proto"],
    "status": ["status", "state", "res", "result"],
    "action": ["action", "act"],
    "severity": ["severity", "sev", "level", "priority"],
    "event_type": ["event_type", "event", "type", "activity", "log_type"],
    "event_id": ["event_id", "eid", "id"],
    "provider": ["provider", "vendor", "app", "application"],
    "attack_type": ["attack_type", "attack", "label", "class", "attack_name", "category"],
    "suspicious": ["suspicious", "is_attack", "is_malicious", "anomaly"]
}

class CSVParser(BaseParser):
    """Parses CSV security log files with dynamic header auto-mapping."""

    def parse_file(
        self, filepath: str, organization: Optional[str] = None, source: Optional[str] = None
    ) -> Generator[ParsedRecord, None, None]:
        filename = os.path.basename(filepath)
        source_name = source or filename

        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
        file_obj = None
        
        for enc in encodings:
            try:
                f = open(filepath, "r", encoding=enc, errors="replace")
                # Test reading header line
                pos = f.tell()
                first_line = f.readline()
                f.seek(pos)
                if first_line:
                    file_obj = f
                    break
            except Exception:
                continue

        if not file_obj:
            yield ParsedRecord(
                source=source_name,
                source_type="CSV",
                log_file=filename,
                parser_status="PARSED_WITH_WARNINGS",
                parser_warning="Could not open CSV file with supported encodings."
            )
            return

        try:
            reader = csv.reader(file_obj)
            try:
                headers = next(reader)
            except StopIteration:
                file_obj.close()
                return

            # Clean headers
            headers_clean = [h.strip().strip('"').strip("'") for h in headers]
            headers_lower = [h.lower().replace(" ", "_") for h in headers_clean]

            # Build column mapping
            col_map: Dict[str, int] = {}
            for target_field, aliases in ALIAS_MAP.items():
                for alias in aliases:
                    if alias in headers_lower:
                        idx = headers_lower.index(alias)
                        if target_field not in col_map:
                            col_map[target_field] = idx

            for row_idx, row in enumerate(reader, start=2):
                if not row or not any(field.strip() for field in row):
                    continue  # Skip empty lines

                try:
                    row_data = {}
                    for idx, val in enumerate(row):
                        header_key = headers_clean[idx] if idx < len(headers_clean) else f"col_{idx}"
                        row_data[header_key] = val.strip()

                    def get_mapped_val(field_name: str) -> Optional[str]:
                        if field_name in col_map and col_map[field_name] < len(row):
                            v = row[col_map[field_name]].strip()
                            return v if v != "" else None
                        return None

                    raw_line = ",".join(row)

                    parsed = ParsedRecord(
                        timestamp=get_mapped_val("timestamp"),
                        organization=organization,
                        source=source_name,
                        source_type="CSV",
                        hostname=get_mapped_val("hostname"),
                        ip_address=get_mapped_val("ip_address"),
                        destination_ip=get_mapped_val("destination_ip"),
                        source_port=get_mapped_val("source_port"),
                        destination_port=get_mapped_val("destination_port"),
                        user=get_mapped_val("user"),
                        event_type=get_mapped_val("event_type"),
                        event_id=get_mapped_val("event_id"),
                        provider=get_mapped_val("provider"),
                        protocol=get_mapped_val("protocol"),
                        status=get_mapped_val("status"),
                        action=get_mapped_val("action"),
                        severity=get_mapped_val("severity"),
                        attack_type=get_mapped_val("attack_type"),  # ONLY preserved from original log if column exists
                        suspicious=get_mapped_val("suspicious"),   # ONLY preserved from original log if column exists
                        raw_log=raw_line,
                        raw_data=row_data,
                        log_file=filename,
                        parser_status="SUCCESS",
                        parser_warning=None
                    )
                    yield parsed

                except Exception as row_err:
                    yield ParsedRecord(
                        organization=organization,
                        source=source_name,
                        source_type="CSV",
                        raw_log=",".join(row) if isinstance(row, list) else str(row),
                        log_file=filename,
                        parser_status="PARSED_WITH_WARNINGS",
                        parser_warning=f"Malformed CSV row #{row_idx}: {str(row_err)}"
                    )
        finally:
            if file_obj:
                file_obj.close()
