"""Transparent risk prioritization, not a probability that software is secure."""
from collections import Counter
from math import log2

WEIGHTS = {"CRITICAL": 40, "HIGH": 16, "MEDIUM": 6, "LOW": 2}
CAPS = {"CRITICAL": 49, "HIGH": 69, "MEDIUM": 89, "LOW": 99}


def classify_finding(finding):
    severity = str(finding.get("severity") or "").upper()
    if severity in WEIGHTS:
        return severity
    likelihood, impact = str(finding.get("likelihood") or "").upper(), str(finding.get("impact") or "").upper()
    if likelihood == impact == "HIGH":
        return "CRITICAL"
    if "HIGH" in (likelihood, impact):
        return "HIGH"
    return "MEDIUM" if "MEDIUM" in (likelihood, impact) else "LOW"


def generate_summary(findings, coverage=None, eligible_files=None):
    counts = Counter(classify_finding(finding) for finding in findings)
    issues = {}
    for finding in findings:
        category = finding.get("category") or finding.get("rule_id")
        location = finding.get("line")
        if location is None:
            location = finding.get("rule_id")
        key = (finding.get("file_path", "snippet"), location, category)
        severity = classify_finding(finding)
        if key not in issues or WEIGHTS[severity] > WEIGHTS[issues[key]]:
            issues[key] = severity
    units = Counter(issues.values())
    burden = sum(WEIGHTS[severity] * log2(1 + count) for severity, count in units.items())
    score = round(100 / (1 + burden / 40))
    for severity in units:
        score = min(score, CAPS[severity])
    state = "assessed"
    explanation = "Severity weights: critical 40, high 16, medium 6, low 2. Risk burden = sum(weight × log2(1 + distinct issues per severity)); score = round(100 / (1 + burden / 40)). Highest-severity ceilings: 49/69/89/99. Duplicate rules at the same location/category count once. Clean files cannot dilute findings."
    if coverage is not None:
        core_failed = any(check.get("status") == "failed" and check.get("scanner_name") in ("Semgrep", "Secrets") for check in coverage)
        if eligible_files == 0 or core_failed:
            score, state = None, "unavailable"
            explanation += " No score is issued when no files are eligible or a core scan fails."
        elif any(check.get("status") not in ("completed", "not_applicable") for check in coverage):
            score, state = min(score, 79), "provisional"
            explanation += " Incomplete coverage makes this provisional and caps it at 79. Review missing checks before relying on it."
    return {"security_score": score, "critical": counts["CRITICAL"], "high": counts["HIGH"],
            "medium": counts["MEDIUM"], "low": counts["LOW"], "score_status": state,
            "score_explanation": explanation, "scoring_version": "2.0", "distinct_issues": len(issues)}
