import hashlib
import re
from datetime import datetime
from typing import Optional
from .parsers.base import ParsedRecord

SEVERITY_MAPPING = {
    "EMERGENCY": "CRITICAL",
    "FATAL": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "ALERT": "HIGH",
    "ERROR": "HIGH",
    "ERR": "HIGH",
    "HIGH": "HIGH",
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NOTICE": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "DEBUG": "INFO"
}

class SIEMNormalizer:
    """Normalizes SIEM record fields, standardizes timestamps and severities, and calculates SHA-256 fingerprints."""

    @staticmethod
    def normalize_timestamp(ts_str: Optional[str]) -> Optional[str]:
        if not ts_str or not str(ts_str).strip():
            return None

        clean_ts = str(ts_str).strip().replace("T", " ").replace("Z", "")
        # Remove trailing microseconds or timezone offsets for standard parsing if present
        clean_ts = re.sub(r"\.\d+", "", clean_ts)
        clean_ts = re.sub(r"[\+\-]\d{2}:\d{2}$", "", clean_ts)

        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
            "%b %d %H:%M:%S",
            "%b %d %Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%y %H:%M:%S",
            "%Y-%m-%d",
        ]

        current_year = datetime.now().year
        for fmt in formats:
            try:
                dt = datetime.strptime(clean_ts, fmt)
                if fmt == "%b %d %H:%M:%S":
                    dt = dt.replace(year=current_year)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue

        # If custom string, return trimmed string or None
        if len(clean_ts) >= 10:
            return clean_ts[:19]
        return None

    @staticmethod
    def normalize_severity(sev_str: Optional[str]) -> Optional[str]:
        if not sev_str or not str(sev_str).strip():
            return None
        upper_sev = str(sev_str).strip().upper()
        return SEVERITY_MAPPING.get(upper_sev, upper_sev)

    @staticmethod
    def generate_fingerprint(record: ParsedRecord) -> str:
        """Derives SHA-256 fingerprint for duplicate tracking."""
        components = [
            str(record.timestamp or ""),
            str(record.source or ""),
            str(record.ip_address or ""),
            str(record.destination_ip or ""),
            str(record.event_id or ""),
            str(record.raw_log or "")[:200]
        ]
        raw_str = "||".join(components)
        return hashlib.sha256(raw_str.encode("utf-8", errors="ignore")).hexdigest()

    @classmethod
    def normalize_record(cls, record: ParsedRecord) -> ParsedRecord:
        """Standardizes a ParsedRecord object into the normalized SIEM schema."""
        record.timestamp = cls.normalize_timestamp(record.timestamp)
        record.severity = cls.normalize_severity(record.severity)

        # Standardize strings (None if empty string)
        for attr in [
            "hostname", "ip_address", "destination_ip", "source_port",
            "destination_port", "user", "event_type", "event_id",
            "provider", "protocol", "status", "action", "attack_type", "suspicious"
        ]:
            val = getattr(record, attr)
            if val is not None:
                val_str = str(val).strip()
                setattr(record, attr, val_str if val_str != "" else None)

        # Build SHA-256 fingerprint
        fingerprint = cls.generate_fingerprint(record)
        setattr(record, "_fingerprint", fingerprint)

        return record
