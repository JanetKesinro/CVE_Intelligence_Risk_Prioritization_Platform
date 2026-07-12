"""
Client for the free NIST National Vulnerability Database (NVD) API v2.0.

No API key or paid service is required. Requests are made directly to
https://services.nvd.nist.gov/rest/json/cves/2.0 to fetch published CVE
metadata (description, CVSS score/vector, CWE weaknesses, and affected
vendor/product info) so it can be shown alongside the local business-context
risk score.
"""

from dataclasses import dataclass, field

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_SECONDS = 10


@dataclass
class CveEnrichment:
    cve_id: str
    description: str
    cvss_score: float | None
    cvss_version: str | None
    severity: str | None
    attack_vector: str | None
    attack_complexity: str | None
    published_date: str | None
    last_modified_date: str | None
    cwe_ids: list[str] = field(default_factory=list)
    vendor_products: list[str] = field(default_factory=list)


@dataclass
class NvdLookupResult:
    success: bool
    data: CveEnrichment | None = None
    error: str | None = None


def _format_date(raw: str | None) -> str | None:
    if not raw:
        return None
    # NVD dates look like "2024-04-12T00:00:00.000"
    date_part = raw.split("T")[0]
    return date_part


def _extract_description(cve: dict) -> str:
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            return entry.get("value", "").strip()
    return "No description available."


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _extract_cvss(cve: dict) -> tuple[
    float | None, str | None, str | None, str | None, str | None
]:
    """Returns (score, version, severity, attack_vector, attack_complexity).

    Prefers the newest CVSS version available (v3.1 -> v3.0 -> v2.0), since
    that's what NVD itself treats as the primary metric.
    """
    metrics = cve.get("metrics", {})

    for key, version in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
    ):
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            cvss_data = entry.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
            attack_vector = cvss_data.get("attackVector")
            attack_complexity = cvss_data.get("attackComplexity")
            return score, version, severity, attack_vector, attack_complexity

    entries = metrics.get("cvssMetricV2")
    if entries:
        entry = entries[0]
        cvss_data = entry.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = entry.get("baseSeverity") or (
            _severity_from_score(score) if score is not None else None
        )
        attack_vector = cvss_data.get("accessVector")
        attack_complexity = cvss_data.get("accessComplexity")
        return score, "2.0", severity, attack_vector, attack_complexity

    return None, None, None, None, None


def _extract_cwe_ids(cve: dict) -> list[str]:
    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for entry in weakness.get("description", []):
            if entry.get("lang") == "en":
                value = entry.get("value", "").strip()
                if value and value not in cwe_ids and "NVD-CWE-noinfo" != value:
                    cwe_ids.append(value)
    return cwe_ids


def _extract_vendor_products(cve: dict, limit: int = 6) -> list[str]:
    vendor_products: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                parts = criteria.split(":")
                # cpe:2.3:part:vendor:product:version:...
                if len(parts) > 4:
                    vendor = parts[3].replace("_", " ").strip()
                    product = parts[4].replace("_", " ").strip()
                    if vendor and vendor != "*" and product and product != "*":
                        label = f"{vendor.title()} / {product.title()}"
                        if label not in vendor_products:
                            vendor_products.append(label)
                if len(vendor_products) >= limit:
                    return vendor_products
    return vendor_products


def fetch_cve_details(cve_id: str) -> NvdLookupResult:
    """Fetch and normalize CVE metadata from the free NVD API.

    Returns an `NvdLookupResult` with either a populated `CveEnrichment` in
    `data`, or a human-readable `error` message suitable for display.
    """
    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )
    except requests.exceptions.Timeout:
        return NvdLookupResult(
            success=False,
            error="The NVD API took too long to respond. Please try again.",
        )
    except requests.exceptions.RequestException:
        return NvdLookupResult(
            success=False,
            error="Could not reach the NVD API. Check your connection and try again.",
        )

    if response.status_code == 404:
        return NvdLookupResult(
            success=False,
            error=f"{cve_id} was not found in the NVD database.",
        )

    if response.status_code == 429:
        return NvdLookupResult(
            success=False,
            error="The NVD API is rate-limiting requests right now. Please wait a "
            "moment and try again.",
        )

    if response.status_code != 200:
        return NvdLookupResult(
            success=False,
            error=f"The NVD API returned an unexpected error (HTTP {response.status_code}).",
        )

    try:
        payload = response.json()
    except ValueError:
        return NvdLookupResult(
            success=False,
            error="The NVD API returned a response that could not be parsed.",
        )

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return NvdLookupResult(
            success=False,
            error=f"{cve_id} was not found in the NVD database.",
        )

    cve = vulnerabilities[0].get("cve", {})
    score, version, severity, attack_vector, attack_complexity = _extract_cvss(cve)

    enrichment = CveEnrichment(
        cve_id=cve.get("id", cve_id),
        description=_extract_description(cve),
        cvss_score=score,
        cvss_version=version,
        severity=severity.upper() if severity else None,
        attack_vector=attack_vector,
        attack_complexity=attack_complexity,
        published_date=_format_date(cve.get("published")),
        last_modified_date=_format_date(cve.get("lastModified")),
        cwe_ids=_extract_cwe_ids(cve),
        vendor_products=_extract_vendor_products(cve),
    )
    return NvdLookupResult(success=True, data=enrichment)
