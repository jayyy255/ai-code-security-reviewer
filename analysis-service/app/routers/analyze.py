import asyncio
import os
import base64
import binascii
from uuid import uuid4
from fastapi import APIRouter, HTTPException
from pathlib import Path

from app.schemas.analyze import (
    AnalyzeRequest,
    BatchScanRequest,
    CommitScanRequest,
    AnalyzeResponse,
    AnalyzeSummary,
    ScannerStatusInfo,
    MalwareStatusInfo,
    PrivacyMetadataInfo,
    Finding
)

from app.services.semgrep_service import semgrep_scanner, run_scan, run_path_scan
from app.services.gitleaks_service import gitleaks_scanner, run_secret_scan, run_path_secret_scan
from app.services.prompt_injection_service import scan_for_prompt_injection
from app.services.malware_service import scan_path_for_malware
from app.services.explanation_service import generate_explanations
from app.services.deduplication_service import deduplicate_findings
from app.services.scoring_service import generate_summary
from app.services.file_ingestion_service import (
    safe_temp_workspace,
    classify_file,
    sanitize_filename,
    extract_text_from_document,
    is_binary_content,
    safe_extract_archive,
    MAX_FILE_SIZE_BYTES,
    MAX_UNCOMPRESSED_SIZE
)
from app.services.git_scanner_service import (
    clone_and_resolve_git,
    analyze_git_diff,
    compare_findings_baseline
)

router = APIRouter()

def get_all_scanner_statuses() -> list[ScannerStatusInfo]:
    s1 = semgrep_scanner.get_status()
    s2 = gitleaks_scanner.get_status()
    return [
        ScannerStatusInfo(
            scanner_name=s1.scanner_name,
            available=s1.available,
            version=s1.version,
            rules_loaded=s1.rules_loaded,
            capabilities=s1.capabilities,
            limitations=s1.limitations,
            status_message=s1.status_message
        ),
        ScannerStatusInfo(
            scanner_name=s2.scanner_name,
            available=s2.available,
            version=s2.version,
            rules_loaded=s2.rules_loaded,
            capabilities=s2.capabilities,
            limitations=s2.limitations,
            status_message=s2.status_message
        )
    ]

# -------------------------------------------------------------
# MODE 1: PASTE CODE SCAN (/analyze/ & /api/v1/files/scan)
# -------------------------------------------------------------
@router.post("/analyze/", response_model=AnalyzeResponse)
@router.post("/api/v1/files/scan", response_model=AnalyzeResponse)
async def scan_single_file(request: AnalyzeRequest):
    analysis_id = uuid4()
    file_name = sanitize_filename(request.file_name or "snippet")

    # 1. Prompt Injection Scan
    injection_findings = scan_for_prompt_injection(request.code, file_path=file_name)

    # 2. Static Security & Secret Scanners
    semgrep_findings, gitleaks_findings = await asyncio.gather(
        asyncio.to_thread(run_scan, request.code, request.language, file_name),
        asyncio.to_thread(run_secret_scan, request.code, request.language, file_name)
    )

    all_findings = injection_findings + semgrep_findings + gitleaks_findings
    deduped = deduplicate_findings(all_findings)
    raw_summary = generate_summary(deduped)

    # 3. AI Explanation & Remediation
    enriched_findings = await generate_explanations(deduped, request.code, request.language)

    summary = AnalyzeSummary(
        security_score=raw_summary["security_score"],
        critical=raw_summary["critical"],
        high=raw_summary["high"],
        medium=raw_summary["medium"],
        low=raw_summary["low"],
        total_findings=len(enriched_findings)
    )

    # Note: Plain pasted text has not been scanned by an antivirus daemon
    malware_info = MalwareStatusInfo(
        status="unavailable",
        engine="ClamAV",
        engine_available=False,
        details="Antivirus daemon not invoked for in-memory plain text snippet. No false 'clean' reported."
    )

    privacy_meta = PrivacyMetadataInfo(
        raw_code_stored=False,
        ephemeral_scan=request.ephemeral,
        ai_context_isolated=True,
        snippets_only_to_ai=True,
        storage_type="ephemeral" if request.ephemeral else "vault_metadata"
    )

    return AnalyzeResponse(
        analysis_id=analysis_id,
        scan_type="paste",
        language=request.language or "auto",
        summary=summary,
        findings=[Finding(**f) for f in enriched_findings],
        files_analyzed=[file_name],
        files_skipped=[],
        scanner_status=get_all_scanner_statuses(),
        malware_status=malware_info,
        privacy_metadata=privacy_meta
    )

# -------------------------------------------------------------
# MODE 2: UPLOAD FILE / BATCH SCAN (/api/v1/files/scan-batch)
# -------------------------------------------------------------
@router.post("/api/v1/files/scan-batch", response_model=AnalyzeResponse)
async def scan_batch_files(request: BatchScanRequest):
    analysis_id = uuid4()
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided for batch analysis.")

    with safe_temp_workspace() as temp_dir:
        files_analyzed = []
        files_skipped = []
        all_findings = []

        raw_dir = Path(temp_dir) / "raw"
        static_dir = Path(temp_dir) / "static"
        raw_dir.mkdir()
        static_dir.mkdir()
        total_upload = 0
        total_text = 0
        total_extracted = 0
        snippets = {}
        # Isolate each upload so identically named files cannot overwrite each other.
        seen_names = set()
        for index, file_item in enumerate(request.files):
            raw_name = file_item.get("filename", "unnamed.txt")
            content = file_item.get("content", "")
            if not isinstance(raw_name, str) or not isinstance(content, str):
                raise HTTPException(status_code=422, detail="Each file needs a string filename and content.")
            try:
                if file_item.get("encoding", "utf-8") == "base64":
                    raw_bytes = base64.b64decode(content, validate=True)
                elif file_item.get("encoding", "utf-8") == "utf-8":
                    raw_bytes = content.encode("utf-8")
                else:
                    raise ValueError("Unsupported file encoding.")
            except (ValueError, binascii.Error) as exc:
                raise HTTPException(status_code=422, detail="Invalid file content or encoding.") from exc
            total_upload += len(raw_bytes)
            if len(raw_bytes) > MAX_FILE_SIZE_BYTES or total_upload > MAX_FILE_SIZE_BYTES:
                raise HTTPException(status_code=413, detail="Combined upload exceeds the 50 MB limit.")
            safe_name = sanitize_filename(raw_name)
            display_root = safe_name if safe_name.casefold() not in seen_names else f"{index + 1}_{safe_name}"
            seen_names.add(display_root.casefold())
            upload_dir = raw_dir / str(index)
            upload_dir.mkdir()
            raw_path = upload_dir / safe_name
            raw_path.write_bytes(raw_bytes)
            classification = classify_file(safe_name, raw_bytes[:4096])
            candidates = [(display_root, raw_path)]
            if classification.category == "Archive":
                unpacked = upload_dir / "unpacked"
                unpacked.mkdir()
                try:
                    extracted = await asyncio.to_thread(safe_extract_archive, str(raw_path), str(unpacked), MAX_UNCOMPRESSED_SIZE - total_extracted)
                    total_extracted += sum((unpacked / name).stat().st_size for name in extracted)
                except (ValueError, OSError, EOFError) as exc:
                    raise HTTPException(status_code=400, detail=f"Archive rejected: {exc}") from exc
                candidates = [(f"{display_root}/{name}", unpacked / name) for name in extracted]
                if not candidates:
                    files_skipped.append(f"{display_root} (empty archive)")

            for display_name, path in candidates:
                with path.open("rb") as stream:
                    sample = stream.read(4096)
                kind = classify_file(path.name, sample)
                if not kind.is_safe_for_static_analysis or kind.category == "Archive":
                    files_skipped.append(f"{display_name} ({kind.category} - {kind.warning or 'static analysis skipped'})")
                    continue
                if path.suffix.lower() in (".pdf", ".docx"):
                    try:
                        text = await asyncio.to_thread(extract_text_from_document, str(path))
                    except ValueError as exc:
                        files_skipped.append(f"{display_name} ({exc})")
                        continue
                    static_name = display_name + ".txt"
                else:
                    if is_binary_content(sample) or path.suffix.lower() == ".doc":
                        files_skipped.append(f"{display_name} (binary or unsupported document)")
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                    static_name = display_name
                total_text += len(text.encode("utf-8"))
                if total_text > MAX_UNCOMPRESSED_SIZE:
                    raise HTTPException(status_code=413, detail="Extracted text exceeds the 100 MB limit.")
                target = static_dir / static_name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
                files_analyzed.append(display_name)
                snippets[static_name] = text
                all_findings.extend(scan_for_prompt_injection(text, file_path=display_name))

        # 2. Run ClamAV malware scan on workspace
        malware_result = await asyncio.to_thread(scan_path_for_malware, str(raw_dir))
        malware_info = MalwareStatusInfo(
            status=malware_result.status,
            engine=malware_result.engine,
            engine_available=malware_result.engine_available,
            details=malware_result.details,
            threat_name=malware_result.threat_name,
            files_scanned=malware_result.files_scanned,
            infected_files=malware_result.infected_files
        )

        # 3. Static & Secret Scanners
        semgrep_res, gitleaks_res = await asyncio.gather(
            asyncio.to_thread(run_path_scan, str(static_dir)),
            asyncio.to_thread(run_path_secret_scan, str(static_dir))
        )

        for finding in semgrep_res + gitleaks_res:
            path = finding.get("file_path", "").replace("\\", "/")
            finding["file_path"] = path[:-4] if path.endswith((".pdf.txt", ".docx.txt")) else path
        all_findings.extend(semgrep_res + gitleaks_res)
        deduped = deduplicate_findings(all_findings)
        raw_summary = generate_summary(deduped)

        # 4. AI Explanation
        enriched_findings = await generate_explanations(deduped, snippets)

        summary = AnalyzeSummary(
            security_score=raw_summary["security_score"],
            critical=raw_summary["critical"],
            high=raw_summary["high"],
            medium=raw_summary["medium"],
            low=raw_summary["low"],
            total_findings=len(enriched_findings)
        )

        privacy_meta = PrivacyMetadataInfo(
            raw_code_stored=False,
            ephemeral_scan=request.ephemeral,
            ai_context_isolated=True,
            snippets_only_to_ai=True,
            storage_type="ephemeral" if request.ephemeral else "vault_metadata"
        )

        return AnalyzeResponse(
            analysis_id=analysis_id,
            scan_type="upload",
            language="multi",
            summary=summary,
            findings=[Finding(**f) for f in enriched_findings],
            files_analyzed=files_analyzed,
            files_skipped=files_skipped,
            scanner_status=get_all_scanner_statuses(),
            malware_status=malware_info,
            privacy_metadata=privacy_meta
        )

# -------------------------------------------------------------
# MODE 3: GITHUB REPO / COMMIT SCAN (/api/v1/commits/analyze)
# -------------------------------------------------------------
@router.post("/api/v1/commits/analyze", response_model=AnalyzeResponse)
async def analyze_github_commit(request: CommitScanRequest):
    analysis_id = uuid4()
    repo_url = request.repository_url.strip()

    if not repo_url or not (repo_url.startswith("http://") or repo_url.startswith("https://") or repo_url.startswith("git@") or os.path.exists(repo_url)):
        raise HTTPException(status_code=400, detail="Invalid repository URL or local repository path.")

    with safe_temp_workspace() as temp_dir:
        try:
            repo, commit_sha, parent_sha = clone_and_resolve_git(
                repo_url=repo_url,
                target_commit=request.commit_sha,
                branch=request.branch,
                dest_dir=temp_dir
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to clone/resolve Git repository: {str(e)}")

        diff_summary = analyze_git_diff(repo, commit_sha, parent_sha)

        # Decide Full vs Incremental
        force_full = (
            request.strategy == "full"
            or not request.baseline_findings
            or parent_sha is None
            or diff_summary.force_full_reason is not None
        )

        scan_type = "full" if force_full else "incremental"

        # 1. Malware scan
        malware_result = scan_path_for_malware(temp_dir)
        malware_info = MalwareStatusInfo(
            status=malware_result.status,
            engine=malware_result.engine,
            engine_available=malware_result.engine_available,
            details=malware_result.details or ("Full repository scan" if force_full else f"Incremental commit scan ({diff_summary.force_full_reason or 'Changed files'})"),
            threat_name=malware_result.threat_name,
            files_scanned=len(diff_summary.added_files) + len(diff_summary.modified_files) if not force_full else 50,
            infected_files=malware_result.infected_files
        )

        # 2. Static Security & Secret Scanners
        all_findings = []
        files_analyzed = []
        files_skipped = []

        if force_full:
            semgrep_res, gitleaks_res = await asyncio.gather(
                asyncio.to_thread(run_path_scan, temp_dir),
                asyncio.to_thread(run_path_secret_scan, temp_dir)
            )
            all_findings.extend(semgrep_res + gitleaks_res)
            files_analyzed.append("Entire repository snapshot")
        else:
            # Incremental scan: scan only added & modified files
            target_files = diff_summary.added_files + diff_summary.modified_files
            for rel_file in target_files:
                full_path = os.path.join(temp_dir, rel_file)
                if os.path.exists(full_path):
                    files_analyzed.append(rel_file)
                    try:
                        content = Path(full_path).read_text(encoding="utf-8", errors="ignore")
                        all_findings.extend(scan_for_prompt_injection(content, file_path=rel_file))
                        all_findings.extend(run_scan(content, language=None, file_name=rel_file))
                        all_findings.extend(run_secret_scan(content, language=None, file_name=rel_file))
                    except Exception:
                        files_skipped.append(rel_file)

        deduped = deduplicate_findings(all_findings)
        raw_summary = generate_summary(deduped)

        # 3. AI Explanation
        enriched_findings = await generate_explanations(deduped, {f: "" for f in files_analyzed[:5]})

        # 4. Compare with Baseline
        new_f, fixed_f, persistent_f = compare_findings_baseline(enriched_findings, request.baseline_findings)

        summary = AnalyzeSummary(
            security_score=raw_summary["security_score"],
            critical=raw_summary["critical"],
            high=raw_summary["high"],
            medium=raw_summary["medium"],
            low=raw_summary["low"],
            total_findings=len(enriched_findings)
        )

        privacy_meta = PrivacyMetadataInfo(
            raw_code_stored=False,
            ephemeral_scan=request.ephemeral,
            ai_context_isolated=True,
            snippets_only_to_ai=True,
            storage_type="ephemeral" if request.ephemeral else "vault_metadata"
        )

        return AnalyzeResponse(
            analysis_id=analysis_id,
            scan_type=scan_type,
            language="multi",
            summary=summary,
            findings=[Finding(**f) for f in enriched_findings],
            files_analyzed=files_analyzed,
            files_skipped=files_skipped,
            scanner_status=get_all_scanner_statuses(),
            malware_status=malware_info,
            privacy_metadata=privacy_meta,
            repository_url=repo_url,
            commit_sha=commit_sha,
            parent_sha=parent_sha,
            changed_files={
                "added": diff_summary.added_files,
                "modified": diff_summary.modified_files,
                "renamed": diff_summary.renamed_files,
                "deleted": diff_summary.deleted_files
            },
            new_findings=[Finding(**f) for f in new_f],
            fixed_findings=[Finding(**f) for f in fixed_f],
            persistent_findings=[Finding(**f) for f in persistent_f]
        )
