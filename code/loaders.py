"""Small, schema-checked loaders for the participant-facing CSV files."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence


CSV_SCHEMAS: Mapping[str, Sequence[str]] = {
    "deletion_requests.csv": (
        "case_id", "email", "requested_at", "reported_status", "reported_at",
        "audit_at", "request_text",
    ),
    "sample_deletion_requests.csv": (
        "case_id", "email", "requested_at", "reported_status", "reported_at",
        "audit_at", "request_text",
    ),
    "sample_output.csv": ("case_id", "deletion_status", "steps_json"),
    "output.csv": ("case_id", "deletion_status", "steps_json"),
    "user_identities.csv": (
        "user_id", "name", "email", "phone", "email_hash", "updated_at",
    ),
    "user_audit_log.csv": (
        "audit_id", "user_id", "event_time", "field_name", "old_value", "new_value",
    ),
    "system_activity.csv": (
        "activity_id", "event_time", "event_type", "source_system", "target_system",
        "resource_id", "reported_result", "details",
    ),
    "deletion_rules.csv": (
        "rule_id", "data_category", "condition", "required_action",
    ),
    "evidence_files.csv": ("file_id", "file_path", "origin", "captured_at"),
}


def parse_timestamp(value: str) -> datetime:
    """Parse the dataset's ISO timestamps as timezone-aware UTC datetimes."""
    text = (value or "").strip()
    if not text:
        raise ValueError("timestamp is empty")
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_csv(path: Path, required_columns: Iterable[str]) -> List[Dict[str, str]]:
    """Load a CSV and fail clearly if its header does not match the contract."""
    expected = list(required_columns)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        actual = reader.fieldnames or []
        missing = [column for column in expected if column not in actual]
        if missing:
            raise ValueError(f"{path.name}: missing required columns: {missing}")
        return [dict(row) for row in reader]


def load_named_csv(dataset_dir: Path, filename: str) -> List[Dict[str, str]]:
    """Load one known participant-facing CSV by its contract name."""
    try:
        schema = CSV_SCHEMAS[filename]
    except KeyError as exc:
        raise ValueError(f"unsupported dataset CSV: {filename}") from exc
    return load_csv(dataset_dir / filename, schema)

