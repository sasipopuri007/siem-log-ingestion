import os
import uuid
import time
from typing import Dict, Any, Optional
from .detector import FormatDetector
from .normalizer import SIEMNormalizer
from .parsers.evtx_parser import EVTXParser
from .parsers.csv_parser import CSVParser
from .parsers.json_parser import JSONParser
from .parsers.syslog_parser import SyslogParser
from .parsers.snort_parser import SnortParser
from .parsers.fallback_parser import FallbackParser
import database

# In-memory status job tracker for background API tracking
PROCESSING_JOBS: Dict[str, Dict[str, Any]] = {}

class LogIngestionPipeline:
    """Orchestrates format detection, parsing, normalization, validation, batch storage, and job status tracking."""

    @staticmethod
    def process_file(
        filepath: str,
        organization: Optional[str] = None,
        source: Optional[str] = None,
        job_id: Optional[str] = None
    ) -> Dict[str, Any]:
        start_time = time.time()
        filename = os.path.basename(filepath)

        # 1. Format Detection
        fmt = FormatDetector.detect(filepath)

        # Instantiate parser
        if fmt == "EVTX":
            parser = EVTXParser()
        elif fmt == "CSV":
            parser = CSVParser()
        elif fmt in ["JSON", "NDJSON"]:
            parser = JSONParser()
        elif fmt == "SYSLOG":
            parser = SyslogParser()
        elif fmt == "SNORT":
            parser = SnortParser()
        else:
            parser = FallbackParser()

        # Job tracker initialization
        current_job_id = job_id or str(uuid.uuid4())
        job_data = {
            "job_id": current_job_id,
            "filename": filename,
            "format_detected": fmt,
            "organization": organization or "Organization 1",
            "source": source or filename,
            "step": "Processing",
            "events_received": 0,
            "events_parsed": 0,
            "events_normalized": 0,
            "events_stored": 0,
            "warnings_count": 0,
            "duplicate_count": 0,
            "status": "PROCESSING",
            "error": None
        }
        PROCESSING_JOBS[current_job_id] = job_data

        batch = []
        batch_size = 500

        try:
            for record in parser.parse_file(filepath, organization=organization, source=source):
                job_data["events_received"] += 1

                # Track parser warnings
                if record.parser_status == "PARSED_WITH_WARNINGS":
                    job_data["warnings_count"] += 1

                job_data["events_parsed"] += 1

                # Normalize record
                try:
                    norm_record = SIEMNormalizer.normalize_record(record)
                    job_data["events_normalized"] += 1
                    
                    rec_dict = norm_record.to_dict()
                    rec_dict["fingerprint"] = getattr(norm_record, "_fingerprint", None)
                    batch.append(rec_dict)
                except Exception as norm_err:
                    job_data["warnings_count"] += 1
                    # Append raw error record
                    batch.append({
                        "timestamp": None,
                        "organization": organization or "Organization 1",
                        "source": source or filename,
                        "source_type": fmt,
                        "raw_log": str(record.raw_log or ""),
                        "log_file": filename,
                        "parser_status": "PARSED_WITH_WARNINGS",
                        "parser_warning": f"Normalization warning: {str(norm_err)}"
                    })

                # Insert batch if limit reached
                if len(batch) >= batch_size:
                    inserted, dups = database.insert_batch(batch)
                    job_data["events_stored"] += inserted
                    job_data["duplicate_count"] += dups
                    batch.clear()

            # Insert remaining batch
            if batch:
                inserted, dups = database.insert_batch(batch)
                job_data["events_stored"] += inserted
                job_data["duplicate_count"] += dups
                batch.clear()

            elapsed = round(time.time() - start_time, 3)
            job_data["elapsed_seconds"] = elapsed
            job_data["step"] = "ML Handoff Ready"
            
            if job_data["warnings_count"] > 0:
                job_data["status"] = "Processing completed with warnings."
            else:
                job_data["status"] = "SUCCESS"

            return job_data

        except Exception as e:
            job_data["status"] = "FAILED"
            job_data["error"] = f"Pipeline processing exception: {str(e)}"
            return job_data

    @staticmethod
    def get_job_status(job_id: str) -> Optional[Dict[str, Any]]:
        return PROCESSING_JOBS.get(job_id)
