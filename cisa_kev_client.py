"""
Client for the free CISA Known Exploited Vulnerabilities (KEV) catalog.

The full catalog is published as a single public JSON file with no API key
required:
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

We fetch the whole catalog (it's a few MB) and look up the requested CVE
locally, since CISA does not offer a per-CVE query endpoint.
"""

from dataclasses import dataclass

import requests

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
REQUEST_TIMEOUT_SECONDS = 15


@dataclass
class KevEntry:
    cve_id: str
    date_added: str | None
    required_action: str | None
    due_date: str | None
    known_ransomware_use: str | None
    vulnerability_name: str | None


@dataclass
class KevCatalogResult:
    success: bool
    entries_by_cve: dict[str, KevEntry] | None = None
    error: str | None = None


@dataclass
class KevLookupResult:
    success: bool
    listed: bool = False
    entry: KevEntry | None = None
    error: str | None = None


def fetch_kev_catalog() -> KevCatalogResult:
    """Fetch and index the full CISA KEV catalog by CVE ID.

    Callers should cache this result (e.g. with `st.cache_data`) since the
    catalog is a multi-megabyte download and only needs refreshing every
    few hours.
    """
    try:
        response = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.exceptions.Timeout:
        return KevCatalogResult(
            success=False,
            error="The CISA KEV catalog took too long to respond.",
        )
    except requests.exceptions.RequestException:
        return KevCatalogResult(
            success=False,
            error="Could not reach the CISA KEV catalog.",
        )

    if response.status_code != 200:
        return KevCatalogResult(
            success=False,
            error=f"CISA KEV catalog returned HTTP {response.status_code}.",
        )

    try:
        payload = response.json()
    except ValueError:
        return KevCatalogResult(
            success=False,
            error="The CISA KEV catalog response could not be parsed.",
        )

    entries_by_cve: dict[str, KevEntry] = {}
    for vuln in payload.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        if not cve_id:
            continue
        entries_by_cve[cve_id.upper()] = KevEntry(
            cve_id=cve_id.upper(),
            date_added=vuln.get("dateAdded"),
            required_action=vuln.get("requiredAction"),
            due_date=vuln.get("dueDate"),
            known_ransomware_use=vuln.get("knownRansomwareCampaignUse"),
            vulnerability_name=vuln.get("vulnerabilityName"),
        )

    return KevCatalogResult(success=True, entries_by_cve=entries_by_cve)


def lookup_kev(cve_id: str, catalog: KevCatalogResult) -> KevLookupResult:
    """Look up a single CVE within an already-fetched catalog result."""
    if not catalog.success or catalog.entries_by_cve is None:
        return KevLookupResult(success=False, error=catalog.error)

    entry = catalog.entries_by_cve.get(cve_id.upper())
    if entry is None:
        return KevLookupResult(success=True, listed=False)

    return KevLookupResult(success=True, listed=True, entry=entry)
