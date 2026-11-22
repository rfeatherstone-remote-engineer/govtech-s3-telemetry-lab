#!/usr/bin/env python3
from __future__ import annotations
import re
from typing import Any

CUI_RE = re.compile(r"\b(?:CONTROLLED\s+UNCLASSIFIED\s+INFORMATION|CUI(?://[A-Z0-9-]+)+)\b", re.IGNORECASE)
SSN_RE = re.compile(r"\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b")
EDIPI_RE = re.compile(r"(?i)\b(dod[_-]?id|edipi|cac[_-]?id|person[_-]?id)\b(\s*[:=]\s*['\"]?)(\d{10})\b")

def sanitize_text(text: str) -> tuple[str, list[str]]:
    findings: list[str] = []
    out = text
    if CUI_RE.search(out):
        findings.append("CUI_MARKING")
        out = CUI_RE.sub("[REDACTED:CUI]", out)
    if SSN_RE.search(out):
        findings.append("SSN")
        out = SSN_RE.sub("[REDACTED:SSN]", out)
    if EDIPI_RE.search(out):
        findings.append("DOD_EDIPI")
        out = EDIPI_RE.sub(r"\1\2[REDACTED:DOD_EDIPI]", out)
    return out, sorted(set(findings))

def _sanitize_value(val: Any) -> tuple[Any, list[str]]:
    if isinstance(val, str):
        return sanitize_text(val)
    if isinstance(val, dict):
        return sanitize_record(val)
    if isinstance(val, list):
        found: set[str] = set()
        items: list[Any] = []
        for item in val:
            c_item, f = _sanitize_value(item)
            items.append(c_item)
            found.update(f)
        return items, sorted(found)
    return val, []

def sanitize_record(record: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    all_found: set[str] = set()
    cleaned: dict[str, Any] = {}
    for k, v in record.items():
        clean_k, fk = sanitize_text(str(k))
        all_found.update(fk)
        cleaned[clean_k], fv = _sanitize_value(v)
        all_found.update(fv)
    return cleaned, sorted(all_found)
