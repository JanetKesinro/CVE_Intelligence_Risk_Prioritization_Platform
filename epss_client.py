"""
Client for the free FIRST.org Exploit Prediction Scoring System (EPSS) API.

No API key required:
https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNNN
"""

from dataclasses import dataclass

import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT_SECONDS = 10


@dataclass
class EpssScore:
    cve_id: str
    probability: float  # 0.0 - 1.0
    percentile: float  # 0.0 - 1.0
    score_date: str | None
    label: str


@dataclass
class EpssLookupResult:
    success: bool
    data: EpssScore | None = None
    error: str | None = None


def _label_for_probability(probability: float) -> str:
    if probability >= 0.50:
        return "Very High"
    if probability >= 0.10:
        return "High"
    if probability >= 0.01:
        return "Moderate"
    return "Low"


def fetch_epss_score(cve_id: str) -> EpssLookupResult:
    """Fetch the current EPSS probability/percentile for a single CVE."""
    try:
        response = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )
    except requests.exceptions.Timeout:
        return EpssLookupResult(
            success=False,
            error="The FIRST EPSS API took too long to respond.",
        )
    except requests.exceptions.RequestException:
        return EpssLookupResult(
            success=False,
            error="Could not reach the FIRST EPSS API.",
        )

    if response.status_code != 200:
        return EpssLookupResult(
            success=False,
            error=f"The FIRST EPSS API returned HTTP {response.status_code}.",
        )

    try:
        payload = response.json()
    except ValueError:
        return EpssLookupResult(
            success=False,
            error="The FIRST EPSS API response could not be parsed.",
        )

    data_rows = payload.get("data", [])
    if not data_rows:
        return EpssLookupResult(
            success=False,
            error=f"No EPSS score is available for {cve_id}.",
        )

    row = data_rows[0]
    try:
        probability = float(row.get("epss"))
        percentile = float(row.get("percentile"))
    except (TypeError, ValueError):
        return EpssLookupResult(
            success=False,
            error="The FIRST EPSS API returned an unexpected score format.",
        )

    return EpssLookupResult(
        success=True,
        data=EpssScore(
            cve_id=cve_id,
            probability=probability,
            percentile=percentile,
            score_date=row.get("date"),
            label=_label_for_probability(probability),
        ),
    )
