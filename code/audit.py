"""Evidence-based case auditing. Evidence is data, never instructions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from typing import Dict, Iterable, List, Mapping, Set, Tuple

try:
    from .evidence import EvidenceDocument, EvidenceIndex
    from .identity import IdentityIndex
    from .loaders import parse_timestamp
except ImportError:  # pragma: no cover
    from evidence import EvidenceDocument, EvidenceIndex
    from identity import IdentityIndex
    from loaders import parse_timestamp


RESOURCE_RE = re.compile(
    r"\b(?:account|search|cache|support|analytics|export|backup|audit_record|"
    r"tombstone|data_flow|telemetry|marketing|delivery)[_-]\d+\b",
    re.IGNORECASE,
)

PREFIX_INFO = {
    "account": ("account_service", "USER_PROFILE"),
    "search": ("search_service", "SEARCH_INDEX_ENTRY"),
    "cache": ("cache_service", "CACHE_ENTRY"),
    "support": ("support_platform", "SUPPORT_MESSAGE"),
    "analytics": ("analytics_platform", "ANALYTICS_PROFILE"),
    "export": ("export_service", "USER_EXPORT"),
    "backup": ("backup_service", "BACKUP_ARCHIVE"),
    "audit_record": ("security_service", "SECURITY_AUDIT_LOG"),
    "tombstone": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "data_flow": ("integration_service", "DATA_FLOW"),
    "telemetry": ("telemetry_service", "PRODUCT_TELEMETRY"),
    "marketing": ("marketing_service", "MARKETING_PROFILE"),
    "delivery": ("delivery_service", "EMAIL_DELIVERY_LOG"),
}


@dataclass
class ResourceObservation:
    system_id: str
    resource_id: str
    data_category: str
    state: str
    evidence_ids: Set[str] = field(default_factory=set)
    activity_ids: Set[str] = field(default_factory=set)
    text: str = ""


@dataclass
class CaseAudit:
    authorized: bool
    user_ids: List[str]
    observations: List[ResourceObservation]
    audit_at: datetime
    risks: List[ResourceObservation] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)


def is_deletion_request(text: str) -> bool:
    """Recognize deletion intent conservatively and reject clearly different actions."""
    lowered = (text or "").casefold()
    if any(term in lowered for term in ("do not close", "reset the login", "correct it", "marketing lists only")):
        return False
    markers = (
        r"\b(delet\w*|erase|erased|remove|removed|close|closed)\b",
        r"\b(eliminar|eliminaci[oó]n|supresi[oó]n|supprimer|suppression)\b",
        "削除",
        "删除",
    )
    return any(re.search(marker, lowered) for marker in markers)


def _resource_info(resource_id: str) -> Tuple[str, str]:
    prefix = resource_id.casefold().split("_", 1)[0]
    if resource_id.casefold().startswith("audit_record_"):
        prefix = "audit_record"
    if resource_id.casefold().startswith("data_flow_"):
        prefix = "data_flow"
    return PREFIX_INFO.get(prefix, ("unknown_service", "UNKNOWN"))


def _state_for(text: str, resource_id: str) -> str:
    lowered = text.casefold()
    if resource_id.casefold().startswith("data_flow_"):
        return "ACTIVE" if any(term in lowered for term in ("enabled", "active", "flow")) else "DISABLED"
    if resource_id.casefold().startswith("backup_"):
        return "ACTIVE" if any(term in lowered for term in ("can be restored", "restore_allowed\": 1", "restore access")) else "BLOCKED"
    if any(term in lowered for term in ("not found", "absent", "rows=0", '"rows": 0')):
        return "ABSENT"
    if "anonym" in lowered and any(term in lowered for term in ("complete", "success", "profile")):
        return "ANONYMIZED"
    if any(term in lowered for term in ("redacted", "redaction", "direct_identifier_removed")):
        return "REDACTED"
    if resource_id.casefold().startswith("audit_record_") and "retain" in lowered:
        return "PRESENT"
    return "PRESENT"


class AuditEngine:
    def __init__(
        self,
        identity_index: IdentityIndex,
        evidence_index: EvidenceIndex,
        activity_rows: Iterable[Mapping[str, str]],
    ) -> None:
        self.identity_index = identity_index
        self.evidence_index = evidence_index
        self.activity_rows = list(activity_rows)
        self.activities_by_resource = defaultdict(list)
        for activity in self.activity_rows:
            self.activities_by_resource[activity["resource_id"].casefold()].append(activity)

    def audit(self, request: Mapping[str, str]) -> CaseAudit:
        audit_at = parse_timestamp(request["audit_at"])
        if not is_deletion_request(request.get("request_text", "")):
            return CaseAudit(False, [], [], audit_at)

        user_ids = self.identity_index.resolve_email(request["email"], audit_at)
        identifiers: Set[str] = {_normalize(request["email"])}
        identifiers.update(
            value
            for values in self.identity_index.identifiers_for_users(user_ids, audit_at).values()
            for value in values
        )
        identifiers.update(user_ids)

        documents: Dict[str, EvidenceDocument] = {}
        for identifier in sorted(identifiers):
            for hit in self.evidence_index.search(identifier, audit_at):
                documents[hit.file_id] = self.evidence_index.documents[hit.file_id]

        grouped: Dict[Tuple[str, str], ResourceObservation] = {}
        for document in documents.values():
            local_resource_ids: Set[str] = set()
            lowered_text = document.text.casefold()
            for identifier in identifiers:
                normalized_identifier = identifier.casefold()
                if not normalized_identifier:
                    continue
                start = 0
                while True:
                    position = lowered_text.find(normalized_identifier, start)
                    if position < 0:
                        break
                    context = document.text[max(0, position - 180): position + len(identifier) + 180]
                    local_resource_ids.update(match.lower() for match in RESOURCE_RE.findall(context))
                    start = position + max(1, len(normalized_identifier))
            for match in sorted(local_resource_ids, key=str.casefold):
                resource_id = match.lower()
                system_id, category = _resource_info(resource_id)
                key = (system_id, resource_id)
                observation = grouped.setdefault(
                    key, ResourceObservation(system_id, resource_id, category, "PRESENT")
                )
                observation.evidence_ids.add(document.file_id)
                observation.text += "\n" + document.text

        for observation in grouped.values():
            observation.state = _state_for(observation.text, observation.resource_id)
            for activity in self.activities_by_resource.get(observation.resource_id.casefold(), []):
                if parse_timestamp(activity["event_time"]) <= audit_at:
                    observation.activity_ids.add(activity["activity_id"])

        risks: List[ResourceObservation] = []
        records: List[ResourceObservation] = []
        for observation in grouped.values():
            if observation.data_category == "DATA_FLOW" and observation.state == "ACTIVE":
                risks.append(observation)
            elif observation.data_category == "BACKUP_ARCHIVE" and observation.state == "ACTIVE":
                risks.append(observation)
            else:
                records.append(observation)

        conflicts = []
        for key, observation in grouped.items():
            text = observation.text.casefold()
            if observation.state == "PRESENT" and any(term in text for term in ("not found", "rows=0", "absent")):
                conflicts.append(f"{key[0]}:{key[1]}")
        return CaseAudit(bool(user_ids), user_ids, sorted(records, key=lambda x: (x.system_id, x.resource_id)), audit_at, sorted(risks, key=lambda x: (x.system_id, x.resource_id)), conflicts)


def _normalize(value: str) -> str:
    return " ".join((value or "").strip().casefold().split())

