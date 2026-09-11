import json
import re
from dataclasses import dataclass
from typing import Dict, Any, Optional

@dataclass
class ParsedRecord:
    timestamp: Optional[str] = None
    organization: Optional[str] = None
    source: Optional[str] = None
    source_type: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[str] = None
    destination_port: Optional[str] = None
    user: Optional[str] = None
    event_type: Optional[str] = None
    event_id: Optional[str] = None
    provider: Optional[str] = None
    protocol: Optional[str] = None
    status: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    attack_type: Optional[str] = None  # ONLY preserved from original log, NEVER generated
    suspicious: Optional[str] = None   # ONLY preserved from original log, NEVER generated
    raw_log: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    log_file: Optional[str] = None
    parser_status: str = "SUCCESS"
    parser_warning: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "organization": self.organization,
            "source": self.source,
            "source_type": self.source_type,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "destination_ip": self.destination_ip,
            "source_port": str(self.source_port) if self.source_port is not None else None,
            "destination_port": str(self.destination_port) if self.destination_port is not None else None,
            "user": self.user,
            "event_type": self.event_type,
            "event_id": str(self.event_id) if self.event_id is not None else None,
            "provider": self.provider,
            "protocol": self.protocol,
            "status": self.status,
            "action": self.action,
            "severity": self.severity,
            "attack_type": self.attack_type,
            "suspicious": self.suspicious,
            "raw_log": self.raw_log,
            "raw_data": json.dumps(self.raw_data) if isinstance(self.raw_data, dict) else (self.raw_data or None),
            "log_file": self.log_file,
            "parser_status": self.parser_status,
            "parser_warning": self.parser_warning,
        }

class BaseParser:
    """Base parser interface for security log parsing."""
    def parse_file(self, filepath: str, organization: Optional[str] = None, source: Optional[str] = None):
        raise NotImplementedError("Subclasses must implement parse_file generator")
