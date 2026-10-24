"""Run the offline Ghost Data Still Exists audit pipeline."""

from __future__ import annotations

import csv
import json
from pathlib import Path

try:
    from .audit import AuditEngine
    from .evidence import EvidenceIndex
    from .identity import IdentityIndex
    from .loaders import load_named_csv
    from .planner import Planner
    from .policy import Policy
    from .validate import validate_rows
except ImportError:  # pragma: no cover - script-style execution.
    from audit import AuditEngine
    from evidence import EvidenceIndex
    from identity import IdentityIndex
    from loaders import load_named_csv
    from planner import Planner
    from policy import Policy
    from validate import validate_rows


def run(repository_root: Path) -> Path:
    dataset_dir = repository_root / "dataset"
    requests = load_named_csv(dataset_dir, "deletion_requests.csv")
    identities = load_named_csv(dataset_dir, "user_identities.csv")
    audit_log = load_named_csv(dataset_dir, "user_audit_log.csv")
    activity = load_named_csv(dataset_dir, "system_activity.csv")
    rules = load_named_csv(dataset_dir, "deletion_rules.csv")
    manifest = load_named_csv(dataset_dir, "evidence_files.csv")

    identity_index = IdentityIndex.from_rows(identities, audit_log)
    evidence_index = EvidenceIndex.from_manifest(dataset_dir, manifest)
    engine = AuditEngine(identity_index, evidence_index, activity)
    planner = Planner(Policy(rules))

    output_rows = []
    for request in sorted(requests, key=lambda row: row["case_id"]):
        audit = engine.audit(request)
        status, steps = planner.plan(audit)
        output_rows.append({
            "case_id": request["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
        })

    evidence_ids = set(evidence_index.documents)
    validate_rows(output_rows, [row["case_id"] for row in requests], evidence_ids)
    output_path = repository_root / "output.csv"
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(output_rows)
    return output_path


if __name__ == "__main__":
    print(run(Path(__file__).resolve().parents[1]))
