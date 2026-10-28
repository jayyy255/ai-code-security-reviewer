import asyncio
from pathlib import Path
from uuid import uuid4
from fastapi import HTTPException
from app.schemas.analyze import AnalyzeResponse, AnalyzeSummary, Finding, PrivacyMetadataInfo, MalwareStatusInfo
from app.services.git_scanner_service import validate_github_target, clone_and_resolve_git
from app.services.repository_review_service import materialize_snapshot, repository_configuration_findings
from app.services.file_ingestion_service import safe_temp_workspace
from app.services.semgrep_service import run_path_scan, semgrep_scanner, LANGUAGE_EXTENSION_MAP
from app.services.gitleaks_service import gitleaks_scanner
from app.services.prompt_injection_service import scan_for_prompt_injection
from app.services.malware_service import scan_path_for_malware
from app.services.dependency_service import scan_dependencies
from app.services.deduplication_service import deduplicate_findings
from app.services.scoring_service import generate_summary, WEIGHTS, classify_finding
from app.services.explanation_service import generate_explanations

_review_slots = asyncio.Semaphore(2)


async def review_repository(request):
    if _review_slots.locked():
        raise HTTPException(503, "Repository scanners are busy. Try again after the current reviews finish.")
    async with _review_slots:
        return await _review_repository(request)


async def _review_repository(request):
    try:
        url = validate_github_target(request.repository_url, request.branch, request.commit_sha)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    with safe_temp_workspace() as workspace:
        repo = None
        try:
            repo, commit_sha, parent_sha = await asyncio.to_thread(clone_and_resolve_git, url, request.commit_sha, request.branch, str(Path(workspace) / "git"))
            snapshot = Path(workspace) / "snapshot"
            files, skipped, texts = await asyncio.to_thread(materialize_snapshot, repo, commit_sha, snapshot)
        except Exception as error:
            # Git stderr may contain server paths or credential-helper output.
            raise HTTPException(400, "Could not fetch the repository snapshot. Use a public GitHub repository and an existing branch or full commit SHA; the clone may also have exceeded its time limit.") from error
        finally:
            if repo is not None:
                repo.close()

        async def run_check(name, callback):
            try:
                output = await asyncio.to_thread(callback)
                return output, {"scanner_name": name, "available": True, "status": "completed", "status_message": "Completed on the selected snapshot."}
            except Exception:
                return [], {"scanner_name": name, "available": False, "status": "failed", "status_message": f"{name} did not complete. Findings from other checks are retained; retry after checking the engine."}

        static, secrets, dependencies, malware = await asyncio.gather(
            run_check("Semgrep", lambda: run_path_scan(str(snapshot))),
            run_check("Secrets", lambda: gitleaks_scanner.scan_path(str(snapshot), strict=True)),
            asyncio.to_thread(scan_dependencies, texts),
            asyncio.to_thread(scan_path_for_malware, str(snapshot)))
        static_findings, static_status = static
        secret_findings, secret_status = secrets
        semgrep_status = semgrep_scanner.get_status()
        static_status.update(rules_loaded=semgrep_status.rules_loaded, capabilities=semgrep_status.capabilities, limitations=semgrep_status.limitations)
        if not gitleaks_scanner.executable and secret_status["status"] == "completed":
            secret_status.update(status="partial", status_message="Fallback secret patterns only; install Gitleaks for the full secret rule set.")
        dependency_findings, dependency_status = dependencies
        coverage = [static_status, secret_status, dependency_status,
            {"scanner_name": "Repository configuration", "available": True, "status": "completed", "status_message": "Checked selected GitHub Actions hazards; infrastructure and source rules run through Semgrep."},
            {"scanner_name": "Prompt injection patterns", "available": True, "status": "completed", "status_message": "Checked tracked text files for known instruction-injection patterns; intent requires review."},
            {"scanner_name": "Malware", "available": malware.engine_available, "status": "completed" if malware.status in ("clean", "infected", "suspicious") else malware.status, "status_message": malware.details or malware.status}]
        if skipped:
            coverage.append({"scanner_name": "File coverage", "available": True, "status": "partial", "status_message": f"{len(skipped)} entries excluded or limited; inspect skipped-file reasons."})
        all_findings = static_findings + secret_findings + dependency_findings + repository_configuration_findings(texts)
        for path, content in texts.items():
            signals = scan_for_prompt_injection(content, file_path=path)
            for signal in signals:
                signal.update(severity="LOW", confidence="LOW", explanation="This text matches a prompt-manipulation pattern. Its presence in a repository is a review signal; confirm that untrusted text reaches an LLM before treating it as an application vulnerability.")
            all_findings.extend(signals)
        if malware.status in ("infected", "suspicious"):
            all_findings.append({"scanner": "clamav", "source": "clamav", "rule_id": "repository-malware", "file_path": "repository", "severity": "CRITICAL" if malware.status == "infected" else "HIGH",
                "category": "malware", "message": malware.threat_name or "Malware engine flagged repository content", "explanation": malware.details,
                "risk": "Flagged content may harm users or build runners if executed.", "remediation": ["Quarantine the flagged files, investigate their origin, and remove or replace them before building or running the repository."]})
        for finding in all_findings:
            finding["file_path"] = finding.get("file_path", "repository").replace("\\", "/")
        findings = deduplicate_findings(all_findings)
        findings.sort(key=lambda finding: (-WEIGHTS[classify_finding(finding)], finding.get("file_path", ""), finding.get("line") or 0))
        eligible = sum(Path(path).suffix.lower() in set(LANGUAGE_EXTENSION_MAP.values()) or Path(path).name.lower() == "dockerfile" for path in texts)
        summary = generate_summary(findings, coverage, eligible)
        # Keep advisory and configuration guidance grounded in its authoritative
        # evidence; AI only enriches source-rule and secret findings.
        await generate_explanations([finding for finding in findings if finding.get("source") not in ("osv", "repository_config", "clamav")])
        return AnalyzeResponse(analysis_id=uuid4(), scan_type="commit", language="multi", repository_url=url.removesuffix(".git"),
            commit_sha=commit_sha, parent_sha=parent_sha, review_scope="Full tracked snapshot at the resolved commit; never a changed-files-only score.",
            summary=AnalyzeSummary(**summary, total_findings=len(findings)), findings=[Finding(**finding) for finding in findings],
            files_analyzed=files, files_skipped=skipped, coverage=coverage, scanner_status=coverage,
            malware_status=MalwareStatusInfo(status=malware.status, engine=malware.engine, engine_available=malware.engine_available, details=malware.details or "", threat_name=malware.threat_name, files_scanned=len(files), infected_files=malware.infected_files),
            privacy_metadata=PrivacyMetadataInfo(raw_code_stored=False, ephemeral_scan=request.ephemeral, storage_type="ephemeral" if request.ephemeral else "vault_metadata"),
            limitations=["Static review cannot find every security risk or prove that a finding is exploitable. No application or dependency code was executed.",
                "Public GitHub repositories only. Default branch HEAD is reviewed unless a branch or commit is selected; past history, submodules, symlinks, generated output and vendored dependencies are excluded.",
                "Limits: 5,000 files, 2 MB per file, 100 MB of snapshot content; shallow clone timeout 60 seconds. Exact supported dependency versions only; unresolved versions and failed lookups are coverage gaps.",
                "Runtime authentication, authorization, business logic, deployed infrastructure and private dependencies need separate verification. A score of 100 is not a security guarantee."])
