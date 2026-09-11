import os
import re
from typing import Generator, Optional
from .base import BaseParser, ParsedRecord

SNORT_PATTERN = re.compile(
    r"^(?:(?P<timestamp>\d{2}\/\d{2}[\-\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?\[\*\*\]\s+\[(?P<sid>\d+:\d+:\d+)\]\s+(?P<msg>.*?)\s+\[\*\*\](?:\s+\[Classification:\s+(?P<classification>.*?)\])?(?:\s+\[Priority:\s+(?P<priority>\d+)\])?\s+(?:\{(?P<protocol>\w+)\}\s+)?(?P<src_ip>[\d\.\:]+)\s+->\s+(?P<dst_ip>[\d\.\:]+)$"
)

class SnortParser(BaseParser):
    """Parses Snort IDS alert log files."""

    def parse_file(
        self, filepath: str, organization: Optional[str] = None, source: Optional[str] = None
    ) -> Generator[ParsedRecord, None, None]:
        filename = os.path.basename(filepath)
        source_name = source or filename

        encodings = ["utf-8", "latin-1", "cp1252"]
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
                match = SNORT_PATTERN.search(line_str)
                if match:
                    gd = match.groupdict()
                    sid = gd.get("sid")
                    msg = gd.get("msg", "Snort Alert")
                    protocol = gd.get("protocol") or "IP"
                    ts = gd.get("timestamp")
                    classification = gd.get("classification")
                    priority = gd.get("priority")

                    src_raw = gd.get("src_ip", "")
                    dst_raw = gd.get("dst_ip", "")

                    src_ip, src_port = src_raw, None
                    if ":" in src_raw:
                        parts = src_raw.split(":")
                        src_ip, src_port = parts[0], parts[1]

                    dst_ip, dst_port = dst_raw, None
                    if ":" in dst_raw:
                        parts = dst_raw.split(":")
                        dst_ip, dst_port = parts[0], parts[1]

                    # Priority map
                    sev_map = {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}
                    severity = sev_map.get(str(priority), "INFO") if priority else None

                    parsed = ParsedRecord(
                        timestamp=ts,
                        organization=organization,
                        source=source_name,
                        source_type="SNORT",
                        ip_address=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        event_type=msg,
                        event_id=sid,
                        provider="Snort IDS",
                        protocol=protocol,
                        status="ALERT",
                        action="ALERTED",
                        severity=severity,
                        attack_type=classification or msg, # SOURCE-PROVIDED ALERT LABEL ONLY
                        suspicious="1",                     # SOURCE-PROVIDED (Snort is an IDS)
                        raw_log=line_str,
                        raw_data={"sid": sid, "classification": classification, "priority": priority, "message": msg},
                        log_file=filename,
                        parser_status="SUCCESS"
                    )
                    yield parsed
                else:
                    # Snort alert non-standard line fallback
                    yield ParsedRecord(
                        organization=organization,
                        source=source_name,
                        source_type="SNORT",
                        raw_log=line_str,
                        log_file=filename,
                        parser_status="PARSED_WITH_WARNINGS",
                        parser_warning="Snort alert line did not match standard alert regex."
                    )
            except Exception as err:
                yield ParsedRecord(
                    organization=organization,
                    source=source_name,
                    source_type="SNORT",
                    raw_log=line_str,
                    log_file=filename,
                    parser_status="PARSED_WITH_WARNINGS",
                    parser_warning=f"Malformed Snort line #{idx}: {str(err)}"
                )
