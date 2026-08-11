"""Finding construction: deduplication, severity, remediation, baseline comparison."""

from agentshield.findings.classifier import build_findings, compare_to_baseline
from agentshield.findings.fingerprint import CATEGORY_CODES, finding_code, fingerprint
from agentshield.findings.remediation import propose

__all__ = [
    "CATEGORY_CODES",
    "build_findings",
    "compare_to_baseline",
    "finding_code",
    "fingerprint",
    "propose",
]
