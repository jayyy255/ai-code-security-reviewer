def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """
    Deduplicates findings across files and scanner engines, retaining the highest severity finding.
    """
    unique = {}
    severity_rank = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    for finding in findings:
        file_path = finding.get("file_path", "snippet")
        line = finding.get("line")
        rule_id = str(finding.get("rule_id", "")).lower()

        vuln_class = [
            v.lower()
            for v in finding.get("vulnerability_class", [])
        ]

        is_secret = (
            "secret" in " ".join(vuln_class)
            or "token" in rule_id
            or "pat" in rule_id
            or "key" in rule_id
        )

        if is_secret:
            key = (file_path, "secret", line)
        else:
            key = (file_path, line, rule_id)

        if key not in unique:
            unique[key] = finding
            continue

        existing = unique[key]
        existing_score = severity_rank.get(existing.get("severity", "LOW").upper(), 1)
        new_score = severity_rank.get(finding.get("severity", "LOW").upper(), 1)

        if new_score > existing_score:
            unique[key] = finding

    return list(unique.values())