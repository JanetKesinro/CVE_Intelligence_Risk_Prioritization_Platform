"""
Risk scoring engine for the AI CVE Risk Prioritizer.

The scoring model is a simple, transparent, rule-based weighting system.
No external/paid APIs are used -- all logic is local and deterministic.
"""

from dataclasses import dataclass


@dataclass
class RiskAssessment:
    score: int
    max_score: int
    level: str
    color: str
    explanation: list[str]
    priority: str
    priority_detail: str


# Weights are intentionally simple and explainable to a security analyst.
WEIGHT_INTERNET_FACING = 30
WEIGHT_ACTIVELY_EXPLOITED = 35
WEIGHT_BUSINESS_CRITICAL = 25
WEIGHT_NO_PATCH_AVAILABLE = 10

MAX_SCORE = (
    WEIGHT_INTERNET_FACING
    + WEIGHT_ACTIVELY_EXPLOITED
    + WEIGHT_BUSINESS_CRITICAL
    + WEIGHT_NO_PATCH_AVAILABLE
)


def assess_risk(
    internet_facing: bool,
    actively_exploited: bool,
    business_critical: bool,
    patch_available: bool,
) -> RiskAssessment:
    score = 0
    explanation: list[str] = []

    if internet_facing:
        score += WEIGHT_INTERNET_FACING
        explanation.append(
            f"+{WEIGHT_INTERNET_FACING} pts -- The affected system is internet-facing, "
            "which significantly widens the pool of potential attackers."
        )
    else:
        explanation.append(
            "+0 pts -- The affected system is not internet-facing, reducing external "
            "attack surface."
        )

    if actively_exploited:
        score += WEIGHT_ACTIVELY_EXPLOITED
        explanation.append(
            f"+{WEIGHT_ACTIVELY_EXPLOITED} pts -- This vulnerability is known to be "
            "actively exploited in the wild, indicating real, ongoing attacker interest."
        )
    else:
        explanation.append(
            "+0 pts -- No known active exploitation has been reported for this "
            "vulnerability."
        )

    if business_critical:
        score += WEIGHT_BUSINESS_CRITICAL
        explanation.append(
            f"+{WEIGHT_BUSINESS_CRITICAL} pts -- The affected asset is business-critical, "
            "so a successful compromise would have significant operational impact."
        )
    else:
        explanation.append(
            "+0 pts -- The affected asset is not classified as business-critical."
        )

    if not patch_available:
        score += WEIGHT_NO_PATCH_AVAILABLE
        explanation.append(
            f"+{WEIGHT_NO_PATCH_AVAILABLE} pts -- No patch is currently available, so the "
            "vulnerability cannot yet be remediated through updates alone."
        )
    else:
        explanation.append(
            "+0 pts -- A patch is available, giving a clear remediation path."
        )

    if score >= 80:
        level, color = "Critical", "#ff4b4b"
        priority = "Immediate (within 24 hours)"
        priority_detail = (
            "This combination of factors represents severe, imminent risk. Treat as an "
            "emergency change: engage incident response if exploitation is suspected, "
            "isolate or restrict access to the asset, and remediate or apply "
            "compensating controls immediately."
        )
    elif score >= 55:
        level, color = "High", "#ff9f1c"
        priority = "Urgent (within 3-5 business days)"
        priority_detail = (
            "Schedule remediation as a high-priority item ahead of routine patch cycles. "
            "Consider temporary compensating controls (network segmentation, WAF rules, "
            "additional monitoring) while remediation is in progress."
        )
    elif score >= 30:
        level, color = "Medium", "#ffd23f"
        priority = "Planned (within 2-4 weeks)"
        priority_detail = (
            "Include in the next scheduled patch or maintenance cycle. Monitor threat "
            "intelligence in case exploitation status changes, which would raise priority."
        )
    else:
        level, color = "Low", "#4cd964"
        priority = "Routine (within standard patch cadence)"
        priority_detail = (
            "No urgent action required. Track and remediate through normal vulnerability "
            "management processes and periodic patch cycles."
        )

    return RiskAssessment(
        score=score,
        max_score=MAX_SCORE,
        level=level,
        color=color,
        explanation=explanation,
        priority=priority,
        priority_detail=priority_detail,
    )
