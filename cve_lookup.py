"""
Lightweight CVE ID validation helpers.

No external/paid APIs are used here -- this module only validates the format
of a CVE identifier locally (e.g. CVE-2024-12345).
"""

import re

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def normalize_cve_id(raw: str) -> str:
    return raw.strip().upper()


def is_valid_cve_id(raw: str) -> bool:
    return bool(CVE_PATTERN.match(normalize_cve_id(raw)))
