"""Deterministic finding, remediation, and verification step planning."""

from __future__ import annotations

from typing import Dict, List, Mapping

try:
    from .audit import CaseAudit, ResourceObservation
    from .policy import Policy
except ImportError:  # pragma: no cover
    from audit import CaseAudit, ResourceObservation
    from policy import Policy


def _step(step_no: int, phase: str, observation: ResourceObservation, operation: str, state: str, evidence_id: str) -> Dict[str, object]:
    return {
        "step_no": step_no,
        "phase": phase,
        "system_id": observation.system_id,
        "resource_id": observation.resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}


class Planner:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def _action(self, observation: ResourceObservation, audit: CaseAudit) -> str:
        return self.policy.action_for(observation.data_category, observation.text, audit.audit_at)

    def _compliant(self, observation: ResourceObservation, audit: CaseAudit) -> bool:
        expected = self._action(observation, audit)
        return {
            "DELETE": observation.state == "ABSENT",
            "REDACT": observation.state == "REDACTED",
            "ANONYMIZE": observation.state == "ANONYMIZED",
            "RETAIN": observation.state == "PRESENT",
        }.get(expected, False)

    def plan(self, audit: CaseAudit) -> tuple[str, List[Dict[str, object]]]:
        if not audit.authorized:
            return "NOT_APPLICABLE", []
        if not audit.user_ids:
            return "INCOMPLETE", []

        violations = [observation for observation in audit.observations if not self._compliant(observation, audit)]
        violations.extend(audit.risks)
        complete = bool(audit.observations) and not violations and not audit.conflicts
        if complete:
            steps: List[Dict[str, object]] = []
            for observation in audit.observations:
                expected = self._action(observation, audit)
                operation, state = {
                    "DELETE": ("VERIFY_RECORD_ABSENT", "ABSENT"),
                    "REDACT": ("VERIFY_RECORD_REDACTED", "REDACTED"),
                    "ANONYMIZE": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
                    "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
                }[expected]
                steps.append(_step(len(steps) + 1, "VERIFICATION", observation, operation, state, sorted(observation.evidence_ids)[0]))
            return "COMPLETE", steps

        findings: List[Dict[str, object]] = []
        remediation: List[tuple[int, ResourceObservation, str, str]] = []
        verification: List[tuple[ResourceObservation, str, str]] = []

        for observation in sorted(audit.risks, key=lambda item: (item.system_id, item.resource_id)):
            if observation.data_category == "DATA_FLOW":
                findings.append(_step(0, "FINDING", observation, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", sorted(observation.evidence_ids)[0]))
                remediation.append((0, observation, "DISABLE_DATA_FLOW", "DISABLED"))
                verification.append((observation, "VERIFY_DATA_FLOW_DISABLED", "DISABLED"))
            else:
                findings.append(_step(0, "FINDING", observation, "REPORT_RESTORE_RISK", "ACTIVE", sorted(observation.evidence_ids)[0]))
                remediation.append((1, observation, "BLOCK_RESTORE", "BLOCKED"))
                verification.append((observation, "VERIFY_RESTORE_BLOCKED", "BLOCKED"))

        for observation in sorted(audit.observations, key=lambda item: (item.system_id, item.resource_id)):
            expected = self._action(observation, audit)
            if self._compliant(observation, audit):
                continue
            finding_operation = "REPORT_EXPOSED_PII" if expected in {"REDACT", "ANONYMIZE"} else "REPORT_REMAINING_RECORD"
            findings.append(_step(0, "FINDING", observation, finding_operation, "PRESENT", sorted(observation.evidence_ids)[0]))
            operation, state = {
                "DELETE": ("DELETE_RECORD", "ABSENT"),
                "REDACT": ("REDACT_RECORD", "REDACTED"),
                "ANONYMIZE": ("ANONYMIZE_RECORD", "ANONYMIZED"),
                "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
            }[expected]
            if operation != "VERIFY_RECORD_PRESENT":
                remediation.append((2, observation, operation, state))
            verification.append((observation, {
                "DELETE_RECORD": "VERIFY_RECORD_ABSENT",
                "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
                "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
                "VERIFY_RECORD_PRESENT": "VERIFY_RECORD_PRESENT",
            }[operation], state))

        findings.sort(key=lambda item: (FINDING_ORDER[item["operation"]], item["system_id"], item["resource_id"]))
        remediation.sort(key=lambda item: (item[0], item[1].system_id, item[1].resource_id))
        verification.sort(key=lambda item: (item[1], item[0].system_id, item[0].resource_id))
        steps = []
        for item in findings:
            item["step_no"] = len(steps) + 1
            steps.append(item)
        for _, observation, operation, state in remediation:
            steps.append(_step(len(steps) + 1, "REMEDIATION", observation, operation, state, ""))
        for observation, operation, state in verification:
            steps.append(_step(len(steps) + 1, "VERIFICATION", observation, operation, state, ""))
        return "INCOMPLETE", steps

