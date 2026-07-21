from url_guard_bot.models import AnalysisResult, Finding, Severity, Verdict


def test_empty_result_is_low_risk() -> None:
    result = AnalysisResult("x", "x")
    assert result.verdict is Verdict.LOW_RISK
    assert result.safe is True


def test_warning_is_suspicious() -> None:
    result = AnalysisResult("x", "x", findings=[Finding("w", Severity.WARNING, "w")])
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.safe is False


def test_error_is_unknown() -> None:
    result = AnalysisResult("x", "x", findings=[Finding("e", Severity.ERROR, "e")])
    assert result.verdict is Verdict.UNKNOWN


def test_danger_has_highest_priority() -> None:
    result = AnalysisResult(
        "x",
        "x",
        findings=[
            Finding("e", Severity.ERROR, "e"),
            Finding("d", Severity.DANGER, "d"),
        ],
    )
    assert result.verdict is Verdict.DANGEROUS
