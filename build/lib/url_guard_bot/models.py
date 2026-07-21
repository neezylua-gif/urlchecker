from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    DANGER = "danger"
    ERROR = "error"


class Verdict(StrEnum):
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    severity: Severity
    message: str


@dataclass(frozen=True, slots=True)
class RedirectStep:
    source_url: str
    target_url: str
    status_code: int
    kind: str = "http"


@dataclass(slots=True)
class AnalysisResult:
    requested_url: str
    display_url: str
    normalized_url: str | None = None
    final_url: str | None = None
    status_code: int | None = None
    findings: list[Finding] = field(default_factory=list)
    redirects: list[RedirectStep] = field(default_factory=list)
    elapsed_ms: int = 0

    @property
    def verdict(self) -> Verdict:
        severities = {finding.severity for finding in self.findings}
        if Severity.DANGER in severities:
            return Verdict.DANGEROUS
        if Severity.ERROR in severities:
            return Verdict.UNKNOWN
        if Severity.WARNING in severities:
            return Verdict.SUSPICIOUS
        return Verdict.LOW_RISK

    @property
    def safe(self) -> bool:
        """Compatibility property: true only when no warning/error was found."""
        return self.verdict is Verdict.LOW_RISK
