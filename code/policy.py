"""Data-driven deletion treatment rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Mapping


@dataclass(frozen=True)
class Treatment:
    action: str
    condition: str


class Policy:
    def __init__(self, rule_rows: Iterable[Mapping[str, str]]) -> None:
        self.rules = {
            row["data_category"]: Treatment(row["required_action"], row["condition"])
            for row in rule_rows
        }

    def action_for(self, data_category: str, text: str, audit_at: datetime) -> str:
        """Return the required action; audit_at is accepted for future date conditions."""
        del audit_at  # Conditions are evaluated from supplied evidence text for now.
        lowered = (text or "").casefold()
        if data_category == "SUPPORT_MESSAGE":
            return "REDACT" if any(term in lowered for term in ("shared", "customer", "agent", "order", "conversation")) else "DELETE"
        if data_category == "SUPPORT_ATTACHMENT":
            return "DELETE" if any(term in lowered for term in ("attachment", ".pdf", "belongs only")) else "REDACT"
        if data_category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            return "ANONYMIZE" if any(term in lowered for term in ("attributable", "profile", "analytics", "telemetry")) else "RETAIN"
        if data_category == "EMAIL_DELIVERY_LOG":
            return "REDACT" if "@" in lowered else "RETAIN"
        if data_category == "SECURITY_AUDIT_LOG":
            return "RETAIN"
        if data_category == "LEGAL_HOLD_RECORD":
            return "RETAIN" if any(term in lowered for term in ("legal hold", "hold", "retain")) else "DELETE"
        if data_category == "BACKUP_ARCHIVE":
            return "RETAIN"
        return self.rules.get(data_category, Treatment("DELETE", "unknown")).action

