import os
import re
import xml.etree.ElementTree as ET
from typing import Generator, Optional, Dict, Any, List
from Evtx.Evtx import Evtx
from .base import BaseParser, ParsedRecord

# Regex patterns for IP address detection in EVTX XML/Data
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b")

# EVTX Field Name Aliases (normalized to lowercase)
SRC_IP_KEYS = ["ipaddress", "srcip", "sourceaddress", "clientaddress", "workstationip", "calleraddress", "networkaddress", "sourceip", "srcaddress", "clientip", "remoteaddress", "remoteip"]
DST_IP_KEYS = ["destip", "destinationaddress", "targetaddress", "serverip", "destaddress", "destinationip", "serveraddress", "targetip", "dstip", "dstaddress"]
SRC_PORT_KEYS = ["ipport", "srcport", "sourceport", "clientport", "callerport", "sourceportnumber", "srcportnum"]
DST_PORT_KEYS = ["destport", "destinationport", "targetport", "serverport", "destinationportnumber", "dstport", "dstportnum"]
USER_KEYS = ["targetusername", "subjectusername", "user", "accountname", "targetuser", "subjectuser", "username", "logonuser", "workstationuser"]
HOST_KEYS = ["workstationname", "workstation", "targetservername", "hostname", "machinename", "destinationhostname", "sourcehostname", "computer"]
PROTO_KEYS = ["authenticationpackagename", "logonprocessname", "protocol", "layername", "transmittedservices", "networkprotocol", "securitypackagename"]
STATUS_KEYS = ["status", "substatus", "logontype", "resultcode", "failurereason"]
ACTION_KEYS = ["task", "audit", "accesses", "accessmask", "privilegelist", "processname", "commandline"]

INVALID_PLACEHOLDERS = ["-", "0", "0x0", "", "none", "null", "::1", "127.0.0.1"]

class EVTXParser(BaseParser):
    """Parses Windows Event Log (.evtx) files using python-evtx with comprehensive EventData/XML extraction."""

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
                        
                        def strip_ns(tag):
                            return tag.split('}')[-1] if '}' in tag else tag

                        system_data: Dict[str, Any] = {}
                        event_data: Dict[str, Any] = {}

                        # Recursive helper to gather XML element data
                        def extract_xml_nodes(parent):
                            for child in parent:
                                ctag = strip_ns(child.tag)
                                if ctag == "System":
                                    for sys_child in child:
                                        stag = strip_ns(sys_child.tag)
                                        if stag == "Provider":
                                            system_data["Provider"] = sys_child.attrib.get("Name")
                                        elif stag == "TimeCreated":
                                            system_data["TimeCreated"] = sys_child.attrib.get("SystemTime")
                                        elif stag == "EventID":
                                            system_data["EventID"] = sys_child.text
                                        elif stag == "Level":
                                            system_data["Level"] = sys_child.text
                                        elif stag == "Computer":
                                            system_data["Computer"] = sys_child.text
                                        elif stag == "EventRecordID":
                                            system_data["EventRecordID"] = sys_child.text
                                elif ctag in ["EventData", "UserData"]:
                                    for data_child in child:
                                        name = data_child.attrib.get("Name") or strip_ns(data_child.tag)
                                        val = data_child.text or ""
                                        event_data[name] = val
                                else:
                                    extract_xml_nodes(child)

                        extract_xml_nodes(root)

                        # Lowercase lookup dictionary for event_data
                        event_data_lower = {k.lower(): str(v).strip() for k, v in event_data.items() if v is not None}

                        # Helper to fetch value from key aliases
                        def get_alias_value(keys: List[str]) -> Optional[str]:
                            for k in keys:
                                if k in event_data_lower:
                                    val = event_data_lower[k]
                                    if val and val.lower() not in INVALID_PLACEHOLDERS:
                                        return val
                            return None

                        # 1. Extract Source IP & Destination IP
                        src_ip = get_alias_value(SRC_IP_KEYS)
                        dst_ip = get_alias_value(DST_IP_KEYS)

                        # Deep Heuristic Sniffing for IPs if specific alias not found
                        if not src_ip or not dst_ip:
                            found_ips = []
                            for val in event_data_lower.values():
                                if val and val.lower() not in INVALID_PLACEHOLDERS:
                                    m_v4 = IPV4_PATTERN.findall(val)
                                    found_ips.extend(m_v4)
                                    m_v6 = IPV6_PATTERN.findall(val)
                                    found_ips.extend(m_v6)

                            # Deduplicate and filter out loopback/placeholders
                            clean_ips = [ip for ip in found_ips if ip not in INVALID_PLACEHOLDERS]
                            if clean_ips:
                                if not src_ip and len(clean_ips) > 0:
                                    src_ip = clean_ips[0]
                                if not dst_ip and len(clean_ips) > 1 and clean_ips[1] != src_ip:
                                    dst_ip = clean_ips[1]

                        # 2. Extract Source Port & Destination Port
                        src_port = get_alias_value(SRC_PORT_KEYS)
                        dst_port = get_alias_value(DST_PORT_KEYS)

                        # Helper to validate port string
                        def clean_port(p_val: Optional[str]) -> Optional[str]:
                            if not p_val or p_val in INVALID_PLACEHOLDERS:
                                return None
                            if p_val.isdigit() and 1 <= int(p_val) <= 65535:
                                return p_val
                            return None

                        src_port = clean_port(src_port)
                        dst_port = clean_port(dst_port)

                        # 3. Extract User
                        user = get_alias_value(USER_KEYS)
                        # Filter system service accounts if domain\username present
                        if user and "\\" in user:
                            # Keep full domain\user or user part
                            pass

                        # 4. Extract Hostname
                        hostname = system_data.get("Computer") or get_alias_value(HOST_KEYS)
                        if hostname in INVALID_PLACEHOLDERS:
                            hostname = None

                        # 5. Extract Protocol
                        protocol = get_alias_value(PROTO_KEYS) or "SystemLog"

                        # 6. Extract Status
                        status_val = get_alias_value(STATUS_KEYS)
                        logon_type = event_data_lower.get("logontype")
                        status = f"LogonType {logon_type}" if logon_type and logon_type not in INVALID_PLACEHOLDERS else (status_val or "INFO")

                        # 7. Extract Action
                        action = get_alias_value(ACTION_KEYS) or event_data_lower.get("task") or None

                        # 8. Level to Severity Mapping
                        level_raw = system_data.get("Level", "")
                        sev_map = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW", "0": "INFO"}
                        severity = sev_map.get(str(level_raw), None)

                        parsed = ParsedRecord(
                            timestamp=system_data.get("TimeCreated"),
                            organization=organization,
                            source=source_name,
                            source_type="EVTX",
                            hostname=hostname,
                            ip_address=src_ip,
                            destination_ip=dst_ip,
                            source_port=src_port,
                            destination_port=dst_port,
                            user=user,
                            event_type=f"Windows Event {system_data.get('EventID', '')}".strip(),
                            event_id=system_data.get("EventID"),
                            provider=system_data.get("Provider"),
                            protocol=protocol,
                            status=status,
                            action=action,
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
