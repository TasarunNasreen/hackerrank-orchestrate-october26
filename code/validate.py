"""Contract validation for generated output.csv rows."""

from __future__ import annotations

import json
from typing import Iterable, Mapping, Set


STEP_KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
OPERATIONS = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}


def validate_rows(rows: Iterable[Mapping[str, str]], request_case_ids: Iterable[str], evidence_ids: Set[str]) -> None:
    rows = list(rows)
    expected_ids = sorted(request_case_ids)
    actual_ids = [row["case_id"] for row in rows]
    if actual_ids != expected_ids:
        raise ValueError("output case IDs must exactly match sorted deletion requests")
    for row in rows:
        status = row["deletion_status"]
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            raise ValueError(f"invalid deletion_status for {row['case_id']}: {status}")
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid steps_json for {row['case_id']}") from exc
        if not isinstance(steps, list):
            raise ValueError("steps_json must be an array")
        if status == "NOT_APPLICABLE" and steps:
            raise ValueError("NOT_APPLICABLE must have [] steps")
        for index, step in enumerate(steps, 1):
            if set(step) != STEP_KEYS:
                raise ValueError(f"step fields mismatch for {row['case_id']}")
            if step["step_no"] != index or step["phase"] not in PHASES:
                raise ValueError(f"step numbering or phase invalid for {row['case_id']}")
            operation = step["operation"]
            if operation not in OPERATIONS or step["state"] != OPERATIONS[operation]:
                raise ValueError(f"operation/state mismatch for {row['case_id']}")
            evidence_id = step["evidence_id"]
            if evidence_id and evidence_id not in evidence_ids:
                raise ValueError(f"unknown evidence ID for {row['case_id']}: {evidence_id}")
            if step["phase"] == "FINDING" and not evidence_id:
                raise ValueError(f"finding lacks evidence for {row['case_id']}")
            if status == "COMPLETE" and step["phase"] == "VERIFICATION" and not evidence_id:
                raise ValueError(f"complete verification lacks evidence for {row['case_id']}")

