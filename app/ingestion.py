"""
ingestion.py
------------
Data ingestion module for the ISO 27001 Compliance Auditor.

Accepts system configuration telemetry as JSON or CSV and normalises it into a
single flat dictionary of dotted keys (e.g. "identity.mfa_enabled") that the
audit engine can evaluate.

Supported inputs
----------------
1. JSON  — nested object produced by Collect-ISOTelemetry.ps1, e.g.
       {"identity": {"mfa_enabled": true}, "encryption": {...}}
   A flat JSON object with dotted keys also works.

2. CSV   — two layouts are auto-detected:
       a) Key/Value layout   -> columns like: key,value   (or setting,value)
       b) Wide layout        -> one header row of dotted keys, one data row

Type coercion
-------------
CSV values arrive as strings. `coerce()` converts them into bool / int / float /
list / None so comparison operators behave the same as with JSON input.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, Tuple

TRUE_TOKENS = {"true", "yes", "y", "enabled", "on", "1", "pass", "present", "compliant"}
FALSE_TOKENS = {"false", "no", "n", "disabled", "off", "0", "fail", "absent", "notpresent"}
# NOTE: "none" is deliberately NOT a null token. Windows reports a genuine
# absence-of-configuration as the literal string "None" (e.g. an unencrypted
# volume returns disk_encryption_type = "None"), which is a real finding rather
# than missing telemetry. Treating it as null would silently downgrade a FAIL
# to NO_DATA. Truly uncollected values arrive as "" or JSON null.
NULL_TOKENS = {"", "null", "n/a", "na", "nan", "unknown", "notcollected", "notapplicable"}

KEY_COLUMN_CANDIDATES = ("key", "setting", "parameter", "field", "name", "control")
VALUE_COLUMN_CANDIDATES = ("value", "result", "status", "data", "observed")


# ---------------------------------------------------------------------------
# Value coercion
# ---------------------------------------------------------------------------

def coerce(value: Any) -> Any:
    """Best-effort conversion of a raw (usually string) value to a Python type."""
    if value is None:
        return None
    if isinstance(value, (bool, int, float, list, dict)):
        return value

    s = str(value).strip()
    low = s.lower()

    if low in NULL_TOKENS:
        return None
    if low in TRUE_TOKENS:
        return True
    if low in FALSE_TOKENS:
        return False

    # JSON-looking payloads (lists / objects) embedded in a CSV cell
    if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
        try:
            return json.loads(s)
        except (ValueError, TypeError):
            pass

    # Semicolon or pipe separated list
    for sep in (";", "|"):
        if sep in s:
            return [coerce(p) for p in s.split(sep) if p.strip() != ""]

    # Numbers
    try:
        if s.lstrip("-").isdigit():
            return int(s)
        return float(s)
    except ValueError:
        pass

    return s


# ---------------------------------------------------------------------------
# Flattening
# ---------------------------------------------------------------------------

def flatten(obj: Any, prefix: str = "", out: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Flatten a nested dict into dotted keys. Lists are kept intact as values."""
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                flatten(v, key, out)
            else:
                out[key] = coerce(v) if not isinstance(v, list) else [coerce(i) for i in v]
    else:
        out[prefix] = coerce(obj)
    return out


def unflatten(flat: Dict[str, Any]) -> Dict[str, Any]:
    """Inverse of flatten — rebuild a nested dict from dotted keys."""
    nested: Dict[str, Any] = {}
    for key, value in flat.items():
        parts = key.split(".")
        node = nested
        for p in parts[:-1]:
            node = node.setdefault(p, {})
            if not isinstance(node, dict):  # collision guard
                break
        else:
            node[parts[-1]] = value
    return nested


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_json(raw: str | bytes) -> Dict[str, Any]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8-sig", errors="replace")
    data = json.loads(raw)
    if isinstance(data, list):
        if not data:
            raise ValueError("JSON array is empty — nothing to audit.")
        # A list of {key,value} records, or a list with one telemetry object
        if all(isinstance(r, dict) and len(r) <= 3 for r in data) and \
           any(k.lower() in KEY_COLUMN_CANDIDATES for r in data for k in r):
            merged = {}
            for rec in data:
                kcol = next((k for k in rec if k.lower() in KEY_COLUMN_CANDIDATES), None)
                vcol = next((k for k in rec if k.lower() in VALUE_COLUMN_CANDIDATES), None)
                if kcol and vcol:
                    merged[str(rec[kcol])] = rec[vcol]
            data = merged
        else:
            data = data[0]
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object or an array of objects.")
    return flatten(data)


def parse_csv(raw: str | bytes) -> Dict[str, Any]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8-sig", errors="replace")
    raw = raw.lstrip("﻿")

    try:
        dialect = csv.Sniffer().sniff(raw[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel

    rows = list(csv.reader(io.StringIO(raw), dialect))
    rows = [r for r in rows if any(str(c).strip() for c in r)]
    if not rows:
        raise ValueError("CSV file contains no usable rows.")

    header = [h.strip() for h in rows[0]]
    header_low = [h.lower() for h in header]

    # Layout (a): key/value pairs
    kidx = next((i for i, h in enumerate(header_low) if h in KEY_COLUMN_CANDIDATES), None)
    vidx = next((i for i, h in enumerate(header_low) if h in VALUE_COLUMN_CANDIDATES), None)
    if kidx is not None and vidx is not None:
        flat: Dict[str, Any] = {}
        for row in rows[1:]:
            if len(row) <= max(kidx, vidx):
                continue
            key = row[kidx].strip()
            if key:
                flat[key] = coerce(row[vidx])
        return flat

    # Layout (b): wide — header of dotted keys, first data row holds the values
    if len(rows) < 2:
        raise ValueError(
            "CSV has a header but no data row. Use a key,value layout or add a data row.")
    values = rows[1]
    flat = {}
    for i, h in enumerate(header):
        if not h:
            continue
        flat[h] = coerce(values[i]) if i < len(values) else None
    return flat


def parse_bytes(raw: bytes, filename: str) -> Dict[str, Any]:
    """Dispatch on file extension, falling back to content sniffing."""
    name = (filename or "").lower()
    if name.endswith(".json"):
        return parse_json(raw)
    if name.endswith((".csv", ".tsv", ".txt")):
        return parse_csv(raw)
    text = raw.decode("utf-8-sig", errors="replace").lstrip()
    return parse_json(text) if text[:1] in "[{" else parse_csv(text)


# ---------------------------------------------------------------------------
# Validation / summary
# ---------------------------------------------------------------------------

REQUIRED_SECTIONS = [
    "identity", "encryption", "logging", "endpoint_protection",
    "patching", "network", "backup",
]


def validate(flat: Dict[str, Any]) -> Tuple[bool, list, dict]:
    """Return (ok, warnings, summary) describing coverage of the telemetry."""
    warnings = []
    sections = {k.split(".")[0] for k in flat if "." in k}

    for section in REQUIRED_SECTIONS:
        if section not in sections:
            warnings.append(
                f"Section '{section}' missing — related controls will be reported as NO DATA.")

    populated = sum(1 for v in flat.values() if v is not None)
    summary = {
        "total_keys": len(flat),
        "populated_keys": populated,
        "null_keys": len(flat) - populated,
        "sections": sorted(sections),
        "hostname": flat.get("metadata.hostname", "Unknown host"),
        "collected_utc": flat.get("metadata.collected_utc", "Unknown"),
        "os": flat.get("metadata.os_caption", "Unknown"),
        "collector_version": flat.get("metadata.collector_version", "n/a"),
    }
    if not flat:
        warnings.append("No parameters were parsed from the file.")
    return (len(flat) > 0), warnings, summary
