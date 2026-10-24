"""Offline, read-only extraction and search over participant evidence files."""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set

try:
    from .loaders import parse_timestamp
except ImportError:  # pragma: no cover - script-style imports.
    from loaders import parse_timestamp


TOKEN_RE = re.compile(r"[\w@.+%-]+", re.UNICODE)


def _tokens(value: str) -> Set[str]:
    return {token.casefold() for token in TOKEN_RE.findall(value or "")}


@dataclass(frozen=True)
class EvidenceDocument:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime
    media_type: str
    text: str
    structured: Any = None
    readable: bool = True
    error: str = ""


@dataclass(frozen=True)
class EvidenceHit:
    file_id: str
    score: int
    snippet: str


def _safe_manifest_path(dataset_dir: Path, relative_path: str) -> Path:
    root = dataset_dir.resolve()
    candidate = (dataset_dir / relative_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"evidence path escapes dataset directory: {relative_path}")
    return candidate


def _extract_json(path: Path) -> tuple[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return json.dumps(value, ensure_ascii=False, sort_keys=True), value


def _extract_sql(path: Path) -> tuple[str, Any]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(path.read_text(encoding="utf-8"))
        table_names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        tables: Dict[str, List[Dict[str, Any]]] = {}
        fragments: List[str] = []
        for table_name in table_names:
            cursor = connection.execute(
                f'SELECT * FROM "{table_name.replace(chr(34), chr(34) * 2)}"'
            )
            columns = [description[0] for description in cursor.description or ()]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
            tables[table_name] = rows
            fragments.append(table_name)
            fragments.extend(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows)
        return "\n".join(fragments), {"tables": tables}
    finally:
        connection.close()


def _extract_pdf(path: Path) -> str:
    try:
        from pypdf import PdfReader

        return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
    except Exception as first_error:
        try:
            import pdfplumber

            with pdfplumber.open(path) as pdf:
                return "\n".join(page.extract_text() or "" for page in pdf.pages)
        except Exception as second_error:
            raise RuntimeError(f"PDF extraction failed: {first_error}; {second_error}")


def _extract_image(path: Path) -> str:
    """Use local OCR only; never send images to an external service."""
    if not shutil.which("tesseract"):
        raise RuntimeError("image OCR unavailable: local tesseract executable not installed")
    try:
        import pytesseract
        from PIL import Image

        return pytesseract.image_to_string(Image.open(path))
    except Exception as exc:
        raise RuntimeError(f"image OCR failed: {exc}")


def extract_document(dataset_dir: Path, manifest_row: Mapping[str, str]) -> EvidenceDocument:
    """Extract one manifest item; extraction failures remain traceable and non-fatal."""
    file_id = manifest_row["file_id"]
    relative_path = manifest_row["file_path"]
    path = _safe_manifest_path(dataset_dir, relative_path)
    suffix = path.suffix.casefold()
    try:
        if suffix == ".json":
            text, structured = _extract_json(path)
            media_type = "json"
        elif suffix in {".log", ".txt"}:
            text, structured, media_type = path.read_text(encoding="utf-8"), None, "text"
        elif suffix == ".sql":
            text, structured = _extract_sql(path)
            media_type = "sql"
        elif suffix == ".pdf":
            text, structured, media_type = _extract_pdf(path), None, "pdf"
        elif suffix in {".png", ".jpg", ".jpeg", ".webp"}:
            text, structured, media_type = _extract_image(path), None, "image"
        else:
            raise RuntimeError(f"unsupported evidence extension: {suffix or '<none>'}")
        return EvidenceDocument(
            file_id, relative_path, manifest_row["origin"],
            parse_timestamp(manifest_row["captured_at"]), media_type, text, structured,
        )
    except Exception as exc:
        return EvidenceDocument(
            file_id, relative_path, manifest_row["origin"],
            parse_timestamp(manifest_row["captured_at"]), suffix.lstrip(".") or "unknown",
            "", None, False, str(exc),
        )


@dataclass
class EvidenceIndex:
    documents: Dict[str, EvidenceDocument]
    inverted: Dict[str, Set[str]] = field(default_factory=dict)

    @classmethod
    def from_manifest(
        cls, dataset_dir: Path, manifest_rows: Iterable[Mapping[str, str]]
    ) -> "EvidenceIndex":
        documents: Dict[str, EvidenceDocument] = {}
        inverted: Dict[str, Set[str]] = {}
        for row in manifest_rows:
            document = extract_document(dataset_dir, row)
            if document.file_id in documents:
                raise ValueError(f"duplicate evidence file_id: {document.file_id}")
            documents[document.file_id] = document
            for token in _tokens(document.text):
                inverted.setdefault(token, set()).add(document.file_id)
        return cls(documents, inverted)

    def unsupported(self) -> List[EvidenceDocument]:
        return sorted(
            (document for document in self.documents.values() if not document.readable),
            key=lambda document: document.file_id,
        )

    def search(self, query: str, audit_at: Optional[datetime] = None) -> List[EvidenceHit]:
        """Search only readable evidence captured no later than audit_at."""
        terms = _tokens(query)
        if not terms:
            return []
        posting_lists = [self.inverted.get(term, set()) for term in terms]
        if not posting_lists:
            return []
        # Multi-token identifiers (for example a person's name or phone) must
        # match every token; matching any token would flood the audit with decoys.
        candidates = set.intersection(*map(set, posting_lists)) if len(posting_lists) > 1 else set(posting_lists[0])
        hits: List[EvidenceHit] = []
        for file_id in candidates:
            document = self.documents[file_id]
            if not document.readable or (audit_at and document.captured_at > audit_at):
                continue
            lowered = document.text.casefold()
            score = sum(lowered.count(term) for term in terms)
            first_term = next((term for term in terms if term in lowered), "")
            position = lowered.find(first_term) if first_term else 0
            start = max(0, position - 80)
            snippet = document.text[start : start + 240].replace("\n", " ").strip()
            hits.append(EvidenceHit(file_id, score, snippet))
        return sorted(hits, key=lambda hit: (-hit.score, hit.file_id))

