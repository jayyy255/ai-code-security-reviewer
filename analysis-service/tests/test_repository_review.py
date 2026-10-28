import json
from pathlib import Path
import git
import pytest
import requests
from fastapi.testclient import TestClient
from app.main import app
from app.services.git_scanner_service import validate_github_target, analyze_git_diff
from app.services.repository_review_service import materialize_snapshot, repository_configuration_findings
from app.services.dependency_service import parse_dependencies, scan_dependencies
from app.services.scoring_service import generate_summary


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://evil.test/a/b", "https://github.com@127.0.0.1/a/b", "file:///etc", "E:/code/project", "git@github.com:a/b", "https://github.com/a/b?x=y"])
def test_reject_non_github_and_local_targets(url):
    with pytest.raises(ValueError):
        validate_github_target(url)


def test_normalize_target_and_reject_option_injection():
    assert validate_github_target("https://github.com/owner/repo.git/") == "https://github.com/owner/repo.git"
    for branch in ["--upload-pack=bad", "main..hidden", "main\n"]:
        with pytest.raises(ValueError):
            validate_github_target("https://github.com/a/b", branch)


def make_repository(path):
    repo = git.Repo.init(path)
    for index in range(12):
        (path / f"file{index}.py").write_text("answer = 42\n")
    (path / "unsafe.py").write_text('import os\nos.system("ping " + user_input)\n')
    repo.index.add([p.name for p in path.iterdir() if p.is_file()])
    first = repo.index.commit("Existing risk")
    (path / "file0.py").write_text("answer = 43\n")
    repo.index.add(["file0.py"])
    second = repo.index.commit("Unrelated change")
    return repo, first.hexsha, second.hexsha


def test_large_repository_diff_and_full_snapshot(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    repo, first, second = make_repository(source)
    try:
        assert analyze_git_diff(repo, second, first).modified_files == ["file0.py"]
        files, skipped, texts = materialize_snapshot(repo, second, tmp_path / "snapshot")
        assert len(files) == 13
        assert not skipped
        assert "os.system" in texts["unsafe.py"]
    finally:
        repo.close()


def test_snapshot_skips_git_symlinks_and_submodules(tmp_path):
    from io import BytesIO
    from types import SimpleNamespace
    blob = SimpleNamespace(type="blob", mode=0o120000, path="escape.py", size=10, data_stream=BytesIO(b"/etc/hosts"))
    submodule = SimpleNamespace(type="submodule", mode=0o160000, path="module")
    repo = SimpleNamespace(commit=lambda sha: SimpleNamespace(tree=SimpleNamespace(traverse=lambda: [blob, submodule])))
    files, skipped, _ = materialize_snapshot(repo, "sha", tmp_path)
    assert not files and len(skipped) == 2
    assert not (tmp_path / "escape.py").exists()


def test_dependencies_parse_and_report_fixed_versions(monkeypatch):
    from app.services import dependency_service as service
    texts = {"requirements.txt": "flask==0.12\nrequests>=2\n", "package-lock.json": json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.20"}}})}
    packages, gaps = parse_dependencies(texts)
    assert len(packages) == 2 and gaps
    def fake_request(path, payload=None, timeout=8):
        if path == "querybatch":
            return {"results": [{"vulns": [{"id": "GHSA-test"}]}, {}]}
        return {"summary": "Known vulnerability", "database_specific": {"severity": "HIGH"}, "affected": [{"package": {"name": "flask"}, "ranges": [{"events": [{"fixed": "1.0"}]}]}]}
    monkeypatch.setattr(service, "_osv_request", fake_request)
    findings, status = scan_dependencies(texts)
    assert findings[0]["severity"] == "HIGH"
    assert "1.0" in findings[0]["remediation"][0]
    assert status["status"] == "partial"


def test_dependency_outage_is_not_clean(monkeypatch):
    from app.services import dependency_service as service
    def fail(*args, **kwargs):
        raise requests.ConnectionError("offline")
    monkeypatch.setattr(service, "_osv_request", fail)
    findings, status = scan_dependencies({"requirements.txt": "flask==0.12"})
    assert not findings and status["status"] == "failed"


def test_workflow_findings_have_specific_remediation():
    findings = repository_configuration_findings({".github/workflows/ci.yml": "permissions: write-all\nsteps:\n - uses: owner/action@main\n"})
    assert len(findings) == 2
    assert all(f["explanation"] and f["remediation"] and f["snippet"] for f in findings)


def test_docker_cleanup_is_not_prompt_injection():
    from app.services.prompt_injection_service import scan_for_prompt_injection
    assert not scan_for_prompt_injection("RUN apt-get clean && rm -rf /var/lib/apt/lists/*", "Dockerfile")


def test_scoring_severity_duplicates_and_coverage():
    def finding(severity, line=1):
        return {"severity": severity, "file_path": "app.py", "line": line, "category": "injection"}
    critical = generate_summary([finding("CRITICAL")])
    assert critical["security_score"] <= 49
    assert critical["security_score"] == generate_summary([finding("CRITICAL")] * 20)["security_score"]
    scores = [generate_summary([finding(severity)])["security_score"] for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]]
    assert scores == sorted(scores, reverse=True)
    assert generate_summary([finding("HIGH", n) for n in range(5)])["security_score"] < scores[2]
    assert generate_summary([], [{"scanner_name": "Malware", "status": "unavailable"}], 1)["security_score"] == 79
    assert generate_summary([], [{"scanner_name": "Semgrep", "status": "failed"}], 1)["security_score"] is None
    assert generate_summary([], [], 0)["security_score"] is None


def test_repository_endpoint_scans_existing_risk_not_only_diff(tmp_path, monkeypatch):
    from app.services import repository_scan_service as service
    source = tmp_path / "source"
    source.mkdir()
    repo, first, second = make_repository(source)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(service, "clone_and_resolve_git", lambda *args: (repo, second, first))
    monkeypatch.setattr(service, "scan_dependencies", lambda texts: ([], {"scanner_name": "Dependency advisories (OSV)", "available": True, "status": "not_applicable", "status_message": "No manifest"}))
    with TestClient(app) as client:
        response = client.post("/api/v1/commits/analyze", headers={"X-Analysis-Token": "test-analysis-service-token-32-characters"}, json={"repository_url": "https://github.com/owner/repo", "strategy": "incremental", "baseline_findings": [{"rule_id": "forged"}], "ephemeral": True})
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["scan_type"] == "commit" and len(report["files_analyzed"]) == 13
    assert report["commit_sha"] == second
    assert any(f["file_path"] == "unsafe.py" and "os.system" in (f["snippet"] or "") for f in report["findings"])
    assert report["summary"]["security_score"] <= 69
    assert report["coverage"] and report["limitations"]
    assert not report["fixed_findings"]  # Never trust caller-supplied baselines.

    def fail_static(*args):
        raise RuntimeError("Engine unavailable")
    monkeypatch.setattr(service, "clone_and_resolve_git", lambda *args: (git.Repo(source), second, first))
    monkeypatch.setattr(service, "run_path_scan", fail_static)
    with TestClient(app) as client:
        failed = client.post("/api/v1/commits/analyze", headers={"X-Analysis-Token": "test-analysis-service-token-32-characters"}, json={"repository_url": "https://github.com/owner/repo", "ephemeral": True}).json()
    assert failed["summary"]["security_score"] is None
    assert failed["summary"]["score_status"] == "unavailable"
    assert any(check["scanner_name"] == "Semgrep" and check["status"] == "failed" for check in failed["coverage"])
