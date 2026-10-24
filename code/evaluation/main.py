"""Offline evaluation against public sample answers and synthetic tests."""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Set, Tuple

CODE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from audit import AuditEngine, CaseAudit, ResourceObservation, is_deletion_request
from evidence import EvidenceIndex
from identity import IdentityIndex
from loaders import load_named_csv
from planner import Planner
from policy import Policy
from validate import validate_rows


UTC = timezone.utc


def _build_pipeline() -> tuple[AuditEngine, Planner, EvidenceIndex, List[Mapping[str, str]]]:
    dataset = REPO_ROOT / "dataset"
    identities = load_named_csv(dataset, "user_identities.csv")
    audit_log = load_named_csv(dataset, "user_audit_log.csv")
    activity = load_named_csv(dataset, "system_activity.csv")
    manifest = load_named_csv(dataset, "evidence_files.csv")
    evidence = EvidenceIndex.from_manifest(dataset, manifest)
    engine = AuditEngine(IdentityIndex.from_rows(identities, audit_log), evidence, activity)
    planner = Planner(Policy(load_named_csv(dataset, "deletion_rules.csv")))
    return engine, planner, evidence, activity


def _run(requests: Iterable[Mapping[str, str]]) -> List[Dict[str, str]]:
    engine, planner, _, _ = _build_pipeline()
    rows = []
    for request in sorted(requests, key=lambda row: row["case_id"]):
        status, steps = planner.plan(engine.audit(request))
        rows.append({
            "case_id": request["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
        })
    return rows


def _steps(row: Mapping[str, str]) -> List[Mapping[str, object]]:
    value = json.loads(row["steps_json"])
    return value if isinstance(value, list) else []


def _metrics(predicted: List[Mapping[str, str]], expected: List[Mapping[str, str]]) -> Dict[str, object]:
    expected_by_id = {row["case_id"]: row for row in expected}
    predicted_by_id = {row["case_id"]: row for row in predicted}
    ids = sorted(set(expected_by_id) & set(predicted_by_id))
    status_correct = sum(predicted_by_id[i]["deletion_status"] == expected_by_id[i]["deletion_status"] for i in ids)
    row_exact = 0
    sequence_correct = 0
    step_matches = 0
    step_denominator = 0
    field_matches = 0
    field_denominator = 0
    for case_id in ids:
        p_steps, e_steps = _steps(predicted_by_id[case_id]), _steps(expected_by_id[case_id])
        if predicted_by_id[case_id]["deletion_status"] == expected_by_id[case_id]["deletion_status"] and p_steps == e_steps:
            row_exact += 1
        p_sequence = [(s.get("phase"), s.get("system_id"), s.get("resource_id"), s.get("operation"), s.get("state")) for s in p_steps]
        e_sequence = [(s.get("phase"), s.get("system_id"), s.get("resource_id"), s.get("operation"), s.get("state")) for s in e_steps]
        sequence_correct += p_sequence == e_sequence
        step_denominator += max(len(p_steps), len(e_steps))
        step_matches += sum(p == e for p, e in zip(p_steps, e_steps))
        field_denominator += 7 * max(len(p_steps), len(e_steps))
        for p_step, e_step in zip(p_steps, e_steps):
            field_matches += sum(p_step.get(key) == e_step.get(key) for key in e_step)
    return {
        "cases": len(ids),
        "status_accuracy": (status_correct / len(ids)) if ids else 0.0,
        "row_exact_accuracy": (row_exact / len(ids)) if ids else 0.0,
        "step_accuracy": (step_matches / step_denominator) if step_denominator else 0.0,
        "field_accuracy": (field_matches / field_denominator) if field_denominator else 0.0,
        "sequence_accuracy": (sequence_correct / len(ids)) if ids else 0.0,
        "status_correct": status_correct,
        "row_exact": row_exact,
        "step_matches": step_matches,
        "step_denominator": step_denominator,
        "field_matches": field_matches,
        "field_denominator": field_denominator,
    }


def _synthetic_tests() -> Dict[str, str]:
    """Three labelled tests; they never enter official output.csv."""
    policy = Policy([
        {"data_category": "USER_PROFILE", "required_action": "DELETE", "condition": "Always"},
        {"data_category": "BACKUP_ARCHIVE", "required_action": "RETAIN", "condition": "blockable"},
    ])
    planner = Planner(policy)
    results = {}

    # SYNTHETIC 1: unauthorized deletion / account support request.
    results["SYNTHETIC_UNAUTHORIZED_DELETION"] = "PASS" if not is_deletion_request("Please reset my login; do not close the account.") else "FAIL"

    # SYNTHETIC 2: surviving replica plus backup risk requires findings and remediation.
    account = ResourceObservation("account_service", "account_901", "USER_PROFILE", "PRESENT", {"evidence_01"})
    backup = ResourceObservation("backup_service", "backup_901", "BACKUP_ARCHIVE", "ACTIVE", {"evidence_02"})
    status, steps = planner.plan(CaseAudit(True, ["user_901"], [account], datetime(2026, 9, 1, tzinfo=UTC), [backup]))
    ops = [step["operation"] for step in steps]
    results["SYNTHETIC_SURVIVING_REPLICA_BACKUP"] = "PASS" if status == "INCOMPLETE" and "REPORT_REMAINING_RECORD" in ops and "REPORT_RESTORE_RISK" in ops and "BLOCK_RESTORE" in ops else "FAIL"

    # SYNTHETIC 3: later sync/restore risk must remain an active finding.
    flow = ResourceObservation("integration_service", "data_flow_902", "DATA_FLOW", "ACTIVE", {"evidence_03"})
    status, steps = planner.plan(CaseAudit(True, ["user_902"], [], datetime(2026, 9, 1, tzinfo=UTC), [flow]))
    results["SYNTHETIC_LATER_SYNC_RESTORE_RISK"] = "PASS" if status == "INCOMPLETE" and steps[0]["operation"] == "REPORT_ACTIVE_DATA_FLOW" and steps[1]["operation"] == "DISABLE_DATA_FLOW" else "FAIL"
    return results


def main() -> int:
    dataset = REPO_ROOT / "dataset"
    sample_requests = load_named_csv(dataset, "sample_deletion_requests.csv")
    sample_expected = load_named_csv(dataset, "sample_output.csv")
    sample_predicted = _run(sample_requests)
    metrics = _metrics(sample_predicted, sample_expected)
    _, _, evidence, activity = _build_pipeline()

    sample_ids = {row["case_id"] for row in sample_expected}
    invalid_refs = []
    unsupported_refs = []
    for row in sample_predicted:
        for step in _steps(row):
            evidence_id = step.get("evidence_id", "")
            if evidence_id and evidence_id not in evidence.documents:
                invalid_refs.append((row["case_id"], evidence_id))
            elif evidence_id and not evidence.documents[evidence_id].readable:
                unsupported_refs.append((row["case_id"], evidence_id))

    full_output = load_named_csv(REPO_ROOT, "output.csv") if False else list(csv.DictReader((REPO_ROOT / "output.csv").open(encoding="utf-8", newline="")))
    validate_rows(full_output, [row["case_id"] for row in load_named_csv(dataset, "deletion_requests.csv")], set(evidence.documents))
    workflow_mismatches = 0
    identity_unresolved = 0
    conflicts = 0
    timestamp_violations = 0
    engine, _, _, _ = _build_pipeline()
    for request in sample_requests:
        audit = engine.audit(request)
        expected = next(row for row in sample_expected if row["case_id"] == request["case_id"])
        if expected["deletion_status"] != request["reported_status"].replace("PARTIALLY_COMPLETE", "INCOMPLETE"):
            workflow_mismatches += 1
        if request["request_text"] and is_deletion_request(request["request_text"]) and not audit.user_ids:
            identity_unresolved += 1
        conflicts += len(audit.conflicts)
        for document in evidence.documents.values():
            if document.file_id in {step.get("evidence_id") for step in _steps(next(row for row in sample_predicted if row["case_id"] == request["case_id"]))} and document.captured_at > audit.audit_at:
                timestamp_violations += 1

    print("PUBLIC SAMPLE METRICS")
    for key, value in metrics.items():
        print(f"{key}: {value}")
    print("DIAGNOSTICS")
    print("invalid_evidence_references:", len(invalid_refs))
    print("unsupported_evidence_references:", len(unsupported_refs))
    print("unreadable_manifest_items:", len(evidence.unsupported()))
    print("timestamp_cutoff_violations:", timestamp_violations)
    print("identity_unresolved_authorized_cases:", identity_unresolved)
    print("conflicting_evidence_markers:", conflicts)
    print("workflow_claim_mismatches_in_public_answers:", workflow_mismatches)
    print("activity_rows_available_for_cross_check:", len(activity))
    print("SYNTHETIC TESTS")
    synthetic = _synthetic_tests()
    for name, result in synthetic.items():
        print(f"{name}: {result}")
    return 0 if all(result == "PASS" for result in synthetic.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
