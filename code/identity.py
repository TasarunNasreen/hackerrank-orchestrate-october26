"""Current and historical identity resolution for deletion requests."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Mapping, Optional, Set

try:  # Works when launched as ``python code/main.py`` or imported as ``code.identity``.
    from .loaders import parse_timestamp
except ImportError:  # pragma: no cover - exercised by the script-style entry point.
    from loaders import parse_timestamp


IDENTITY_FIELDS = {"name", "email", "phone", "email_hash"}


def _normalize(value: str) -> str:
    return " ".join((value or "").strip().casefold().split())


@dataclass
class IdentityIndex:
    """An index that never uses identity facts newer than the audit cutoff."""

    current_rows: Mapping[str, Mapping[str, str]]
    audit_rows: Iterable[Mapping[str, str]]
    _current_by_user: Dict[str, Mapping[str, str]] = field(init=False, repr=False)
    _events: List[Mapping[str, str]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._current_by_user = {
            str(row["user_id"]): row for row in self.current_rows.values()
        }
        self._events = sorted(
            list(self.audit_rows),
            key=lambda row: parse_timestamp(row["event_time"]),
        )

    @classmethod
    def from_rows(
        cls,
        current_rows: Iterable[Mapping[str, str]],
        audit_rows: Iterable[Mapping[str, str]],
    ) -> "IdentityIndex":
        current = {str(row["user_id"]): row for row in current_rows}
        return cls(current, list(audit_rows))

    def _aliases_at(
        self, audit_at: datetime, field_names: Set[str] = IDENTITY_FIELDS
    ) -> Dict[str, Set[str]]:
        aliases: Dict[str, Set[str]] = defaultdict(set)

        for user_id, row in self._current_by_user.items():
            updated_at = parse_timestamp(row["updated_at"])
            if updated_at <= audit_at:
                for field_name in field_names:
                    value = _normalize(row.get(field_name, ""))
                    if value:
                        aliases[value].add(user_id)

        for row in self._events:
            if parse_timestamp(row["event_time"]) > audit_at:
                break
            user_id = str(row["user_id"])
            if row.get("field_name") not in field_names:
                continue
            for value in (row.get("old_value", ""), row.get("new_value", "")):
                normalized = _normalize(value)
                if normalized:
                    aliases[normalized].add(user_id)
        return aliases

    def resolve(self, identifier: str, audit_at: datetime) -> List[str]:
        """Return all matching user IDs in deterministic order."""
        return sorted(self._aliases_at(audit_at).get(_normalize(identifier), set()))

    def resolve_email(self, email: str, audit_at: datetime) -> List[str]:
        """Resolve the request email; matching is case-insensitive."""
        return sorted(
            self._aliases_at(audit_at, {"email"}).get(_normalize(email), set())
        )

    def identifiers_for_users(
        self, user_ids: Iterable[str], audit_at: datetime
    ) -> Dict[str, Set[str]]:
        """Return all identifier values known for each user by the cutoff."""
        wanted = {str(user_id) for user_id in user_ids}
        result: Dict[str, Set[str]] = {user_id: set() for user_id in wanted}
        for user_id, row in self._current_by_user.items():
            if user_id in wanted and parse_timestamp(row["updated_at"]) <= audit_at:
                result[user_id].update(
                    _normalize(row.get(field_name, ""))
                    for field_name in IDENTITY_FIELDS
                    if _normalize(row.get(field_name, ""))
                )
        for row in self._events:
            if parse_timestamp(row["event_time"]) > audit_at:
                break
            user_id = str(row["user_id"])
            if user_id in wanted and row.get("field_name") in IDENTITY_FIELDS:
                for value in (row.get("old_value", ""), row.get("new_value", "")):
                    normalized = _normalize(value)
                    if normalized:
                        result[user_id].add(normalized)
        return result

