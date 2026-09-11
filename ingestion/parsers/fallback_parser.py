import os
import re
from typing import Generator, Optional
from .base import BaseParser, ParsedRecord

IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
IPV6_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
TIMESTAMP_REGEX = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[\+\-]\d{2}:\d{2})?\b|"
    r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b|"
    r"\b\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2}\b|"
    r"\b\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\b"
)
PORT_REGEX = re.compile(r"\b(?:port|src_port|dst_port|source_port|dest_port)[=:\s]+(\d{1,5})\b", re.IGNORECASE)
USER_REGEX = re.compile(r"\b(?:user|username|account)[=:\s]+([a-zA-Z0-9_\-\.]+)\b", re.IGNORECASE)
PROTOCOL_REGEX = re.compile(r"\b(TCP|UDP|ICMP|HTTP|HTTPS|SSH|FTP|DNS|TELNET|SMTP)\b", re.IGNORECASE)
SEVERITY_REGEX = re.compile(r"\b(EMERGENCY|ALERT|CRITICAL|ERROR|HIGH|WARNING|WARN|MEDIUM|NOTICE|LOW|INFO|DEBUG)\b", re.IGNORECASE)
KEYWORD_REGEX = re.compile(r"\b(login|failed|failure|success|accepted|denied|blocked|allowed|connect|disconnect|dropped|timeout|error|exception|attack|scan|flood)\b", re.IGNORECASE)

class FallbackParser(BaseParser):
    """Generic heuristic fallback parser for unrecognized log formats."""

    def parse_file(
        self, filepath: str, organization: Optional[str] = None, source: Optional[str] = None
    ) -> Generator[ParsedRecord, None, None]:
        filename = os.path.basename(filepath)
        source_name = source or filename

        lines = []
        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
        for enc in encodings:
            try:
                with open(filepath, "r", encoding=enc, errors="replace") as f:
                    lines = f.readlines()
                if lines:
                    break
            except Exception:
                continue

        if not lines:
            yield ParsedRecord(
                organization=organization,
                source=source_name,
                source_type="GENERIC_TEXT",
                raw_log=f"Empty file: {filename}",
                log_file=filename,
                parser_status="PARSED_WITH_WARNINGS",
                parser_warning="Empty or unreadable log file."
            )
            return

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                # Detect timestamps
                ts_match = TIMESTAMP_REGEX.search(line_str)
                ts = ts_match.group(0) if ts_match else None

                # Detect IPv4 & IPv6 using finditer full match strings
                ip_matches = [m.group(0) for m in IPV4_REGEX.finditer(line_str)]
                if not ip_matches:
                    ip_matches = [m.group(0) for m in IPV6_REGEX.finditer(line_str)]
                
                src_ip = ip_matches[0] if len(ip_matches) > 0 else None
                dst_ip = ip_matches[1] if len(ip_matches) > 1 else None

                # Detect user
                user_match = USER_REGEX.search(line_str)
                user = user_match.group(1) if user_match else None

                # Detect port
                port_match = PORT_REGEX.search(line_str)
                port = port_match.group(1) if port_match else None

                # Detect protocol
                proto_match = PROTOCOL_REGEX.search(line_str)
                proto = proto_match.group(1).upper() if proto_match else None

                # Detect severity
                sev_match = SEVERITY_REGEX.search(line_str)
                severity = sev_match.group(1).upper() if sev_match else None

                # Detect keywords for event_type/action
                kw_match = KEYWORD_REGEX.search(line_str)
                event_type = f"Generic Event ({kw_match.group(1)})" if kw_match else "Unstructured Log Record"
                action = kw_match.group(1).upper() if kw_match else None

                # Determine parser warning status
                fields_extracted = any([ts, src_ip, dst_ip, user, port, proto, severity, kw_match])
                status = "PARSED_WITH_WARNINGS"
                warning = "Generic fallback parser used for unstructured record." if not fields_extracted else "Generic fallback parser used: extracted partial heuristic fields."

                parsed = ParsedRecord(
                    timestamp=ts,
                    organization=organization,
                    source=source_name,
                    source_type="GENERIC_TEXT",
                    ip_address=src_ip,
                    destination_ip=dst_ip,
                    source_port=port,
                    user=user,
                    event_type=event_type,
                    protocol=proto,
                    action=action,
                    severity=severity,
                    attack_type=None,  # NEVER invent
                    suspicious=None,   # NEVER invent
                    raw_log=line_str,
                    raw_data={"extracted_fields": {
                        "timestamp": ts, "ip_address": src_ip, "destination_ip": dst_ip,
                        "user": user, "port": port, "protocol": proto, "severity": severity
                    }},
                    log_file=filename,
                    parser_status=status,
                    parser_warning=warning
                )
                yield parsed

            except Exception as line_err:
                yield ParsedRecord(
                    organization=organization,
                    source=source_name,
                    source_type="GENERIC_TEXT",
                    raw_log=line_str,
                    log_file=filename,
                    parser_status="PARSED_WITH_WARNINGS",
                    parser_warning=f"Fallback line #{idx} parse exception: {str(line_err)}"
                )
