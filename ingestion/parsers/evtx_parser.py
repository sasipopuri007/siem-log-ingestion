import os
import xml.etree.ElementTree as ET
from typing import Generator, Optional
from Evtx.Evtx import Evtx
from .base import BaseParser, ParsedRecord

class EVTXParser(BaseParser):
    """Parses Windows Event Log (.evtx) files using python-evtx."""

    def parse_file(
        self, filepath: str, organization: Optional[str] = None, source: Optional[str] = None
    ) -> Generator[ParsedRecord, None, None]:
        filename = os.path.basename(filepath)
        source_name = source or filename

        try:
            with Evtx(filepath) as log:
                for record in log.records():
                    raw_xml = ""
                    try:
                        raw_xml = record.xml()
                        root = ET.fromstring(raw_xml)
                        
                        # Helper to strip XML namespace
                        def strip_ns(tag):
                            return tag.split('}')[-1] if '}' in tag else tag

                        system_data = {}
                        event_data = {}

                        for elem in root:
                            tag_name = strip_ns(elem.tag)
                            if tag_name == "System":
                                for child in elem:
                                    ctag = strip_ns(child.tag)
                                    if ctag == "Provider":
                                        system_data["Provider"] = child.attrib.get("Name")
                                    elif ctag == "TimeCreated":
                                        system_data["TimeCreated"] = child.attrib.get("SystemTime")
                                    elif ctag == "EventID":
                                        system_data["EventID"] = child.text
                                    elif ctag == "Level":
                                        system_data["Level"] = child.text
                                    elif ctag == "Computer":
                                        system_data["Computer"] = child.text
                                    elif ctag == "EventRecordID":
                                        system_data["EventRecordID"] = child.text
                            elif tag_name in ["EventData", "UserData"]:
                                for child in elem:
                                    name = child.attrib.get("Name") or strip_ns(child.tag)
                                    val = child.text or ""
                                    event_data[name] = val

                        # Map EVTX Level to severity
                        level_raw = system_data.get("Level", "")
                        sev_map = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW", "0": "INFO"}
                        severity = sev_map.get(str(level_raw), None)

                        # Extract potential IP and User from EventData if present
                        ip_addr = event_data.get("IpAddress") or event_data.get("SrcIp") or event_data.get("WorkstationIP") or None
                        if ip_addr == "-" or ip_addr == "::1" or ip_addr == "127.0.0.1":
                            pass  # Keep or sanitize if needed
                        
                        dst_ip = event_data.get("DestIp") or event_data.get("DestinationIP") or None
                        user = event_data.get("TargetUserName") or event_data.get("SubjectUserName") or event_data.get("User") or None
                        if user == "-":
                            user = None

                        parsed = ParsedRecord(
                            timestamp=system_data.get("TimeCreated"),
                            organization=organization,
                            source=source_name,
                            source_type="EVTX",
                            hostname=system_data.get("Computer"),
                            ip_address=ip_addr,
                            destination_ip=dst_ip,
                            source_port=event_data.get("IpPort") or event_data.get("SrcPort"),
                            destination_port=event_data.get("DestPort"),
                            user=user,
                            event_type=f"Windows Event {system_data.get('EventID', '')}".strip(),
                            event_id=system_data.get("EventID"),
                            provider=system_data.get("Provider"),
                            protocol="SystemLog",
                            status="INFO",
                            action=event_data.get("Task") or None,
                            severity=severity,
                            attack_type=None,  # NEVER invent
                            suspicious=None,   # NEVER invent
                            raw_log=raw_xml,
                            raw_data={"system": system_data, "event_data": event_data},
                            log_file=filename,
                            parser_status="SUCCESS",
                            parser_warning=None
                        )
                        yield parsed

                    except Exception as rec_err:
                        # Fault tolerant: single EVTX record parsing failed, return partial record
                        yield ParsedRecord(
                            timestamp=None,
                            organization=organization,
                            source=source_name,
                            source_type="EVTX",
                            raw_log=raw_xml or f"Unparseable EVTX record #{getattr(record, 'record_num', 'unknown')}",
                            log_file=filename,
                            parser_status="PARSED_WITH_WARNINGS",
                            parser_warning=f"Malformed EVTX XML record: {str(rec_err)}"
                        )
        except Exception as file_err:
            # File level issue
            yield ParsedRecord(
                timestamp=None,
                organization=organization,
                source=source_name,
                source_type="EVTX",
                raw_log=f"Corrupted or invalid EVTX file: {filename}",
                log_file=filename,
                parser_status="PARSED_WITH_WARNINGS",
                parser_warning=f"EVTX File parsing error: {str(file_err)}"
            )
