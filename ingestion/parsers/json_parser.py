import os
import json
from typing import Generator, Optional, Dict, Any, List
from .base import BaseParser, ParsedRecord
from .csv_parser import ALIAS_MAP

class JSONParser(BaseParser):
    """Parses JSON, JSON Arrays, and NDJSON (JSON Lines) files."""

    def _extract_fields_from_dict(self, data: Dict[str, Any], raw_str: str, filename: str, organization: Optional[str], source_name: str) -> ParsedRecord:
        # Lowercase keys mapping helper
        flat_map: Dict[str, Any] = {}
        def flatten_keys(d, prefix=""):
            for k, v in d.items():
                key_lower = k.lower().replace("-", "_").replace(" ", "_")
                if isinstance(v, dict):
                    flatten_keys(v, prefix=f"{key_lower}_")
                else:
                    flat_map[key_lower] = v
                    if prefix:
                        flat_map[f"{prefix}{key_lower}"] = v

        flatten_keys(data)

        def get_val(field_name: str) -> Optional[str]:
            aliases = ALIAS_MAP.get(field_name, [field_name])
            for alias in aliases:
                if alias in flat_map and flat_map[alias] is not None:
                    v = str(flat_map[alias]).strip()
                    return v if v != "" else None
            return None

        return ParsedRecord(
            timestamp=get_val("timestamp"),
            organization=organization,
            source=source_name,
            source_type="JSON",
            hostname=get_val("hostname"),
            ip_address=get_val("ip_address"),
            destination_ip=get_val("destination_ip"),
            source_port=get_val("source_port"),
            destination_port=get_val("destination_port"),
            user=get_val("user"),
            event_type=get_val("event_type"),
            event_id=get_val("event_id"),
            provider=get_val("provider"),
            protocol=get_val("protocol"),
            status=get_val("status"),
            action=get_val("action"),
            severity=get_val("severity"),
            attack_type=get_val("attack_type"),  # ONLY if present in JSON
            suspicious=get_val("suspicious"),   # ONLY if present in JSON
            raw_log=raw_str,
            raw_data=data,
            log_file=filename,
            parser_status="SUCCESS",
            parser_warning=None
        )

    def parse_file(
        self, filepath: str, organization: Optional[str] = None, source: Optional[str] = None
    ) -> Generator[ParsedRecord, None, None]:
        filename = os.path.basename(filepath)
        source_name = source or filename

        # Read file content safely
        content = ""
        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
        for enc in encodings:
            try:
                with open(filepath, "r", encoding=enc, errors="replace") as f:
                    content = f.read()
                if content:
                    break
            except Exception:
                continue

        if not content.strip():
            yield ParsedRecord(
                source=source_name,
                source_type="JSON",
                log_file=filename,
                parser_status="PARSED_WITH_WARNINGS",
                parser_warning="Empty JSON file."
            )
            return

        trimmed = content.strip()

        # Try parsing as single JSON object or JSON array first
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                parsed_json = json.loads(trimmed)
                if isinstance(parsed_json, dict):
                    yield self._extract_fields_from_dict(parsed_json, json.dumps(parsed_json), filename, organization, source_name)
                    return
                elif isinstance(parsed_json, list):
                    for item in parsed_json:
                        if isinstance(item, dict):
                            yield self._extract_fields_from_dict(item, json.dumps(item), filename, organization, source_name)
                        else:
                            yield ParsedRecord(
                                source=source_name,
                                source_type="JSON",
                                raw_log=str(item),
                                log_file=filename,
                                parser_status="PARSED_WITH_WARNINGS",
                                parser_warning="JSON array item is not an object."
                            )
                    return
            except Exception:
                pass  # Fall through to NDJSON line-by-line parsing

        # Process as NDJSON / JSON Lines (line by line)
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                obj = json.loads(line_str)
                if isinstance(obj, dict):
                    yield self._extract_fields_from_dict(obj, line_str, filename, organization, source_name)
                else:
                    yield ParsedRecord(
                        source=source_name,
                        source_type="NDJSON",
                        raw_log=line_str,
                        raw_data={"value": obj},
                        log_file=filename,
                        parser_status="SUCCESS"
                    )
            except Exception as line_err:
                yield ParsedRecord(
                    organization=organization,
                    source=source_name,
                    source_type="NDJSON",
                    raw_log=line_str,
                    log_file=filename,
                    parser_status="PARSED_WITH_WARNINGS",
                    parser_warning=f"Malformed JSON line #{idx}: {str(line_err)}"
                )
