import os
import tempfile
import git
import pytest
from app.services.git_scanner_service import (
    clone_and_resolve_git,
    analyze_git_diff,
    compare_findings_baseline
)

@pytest.fixture
def sample_git_repo():
    """Creates a local temporary Git repository with multiple commits for testing."""
    temp_dir = tempfile.mkdtemp(prefix="test_repo_")
    repo = git.Repo.init(temp_dir)

    # Commit 1: Initial commit with vulnerable file
    file1 = os.path.join(temp_dir, "app.py")
    with open(file1, "w", encoding="utf-8") as f:
        f.write("import sqlite3\ndef query(uid):\n    return sqlite3.connect('x.db').cursor().execute(f'SELECT * FROM u WHERE id={uid}')\n")
    
    repo.index.add(["app.py"])
    c1 = repo.index.commit("Initial commit with SQL vulnerability")

    # Commit 2: Add second file with hardcoded secret
    file2 = os.path.join(temp_dir, "config.py")
    with open(file2, "w", encoding="utf-8") as f:
        f.write("API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    
    repo.index.add(["config.py"])
    c2 = repo.index.commit("Add config with secret")

    # Commit 3: Modify dependency lockfile
    lockfile = os.path.join(temp_dir, "requirements.txt")
    with open(lockfile, "w", encoding="utf-8") as f:
        f.write("fastapi==0.110.0\n")
    repo.index.add(["requirements.txt"])
    c3 = repo.index.commit("Update requirements lockfile")

    yield temp_dir, c1.hexsha, c2.hexsha, c3.hexsha

    repo.close()

def test_git_first_commit_diff(sample_git_repo):
    repo_dir, c1, c2, c3 = sample_git_repo
    repo = git.Repo(repo_dir)

    diff1 = analyze_git_diff(repo, c1, None)
    assert diff1.force_full_reason is not None
    assert "No parent commit" in diff1.force_full_reason

def test_git_second_commit_incremental_diff(sample_git_repo):
    repo_dir, c1, c2, c3 = sample_git_repo
    repo = git.Repo(repo_dir)

    diff2 = analyze_git_diff(repo, c2, c1)
    assert "config.py" in diff2.added_files
    assert diff2.lockfile_changed is False
    assert diff2.force_full_reason is None

def test_git_lockfile_triggers_full_scan(sample_git_repo):
    repo_dir, c1, c2, c3 = sample_git_repo
    repo = git.Repo(repo_dir)

    diff3 = analyze_git_diff(repo, c3, c2)
    assert diff3.lockfile_changed is True
    assert diff3.force_full_reason is not None
    assert "lockfile" in diff3.force_full_reason.lower()

def test_baseline_findings_comparison():
    baseline = [
        {"rule_id": "python-sql-injection-format", "file_path": "app.py", "line": 3, "message": "SQL flaw"}
    ]
    current = [
        {"rule_id": "python-sql-injection-format", "file_path": "app.py", "line": 3, "message": "SQL flaw"},
        {"rule_id": "aws-access-key", "file_path": "config.py", "line": 1, "message": "AWS Secret"}
    ]

    new_f, fixed_f, persistent_f = compare_findings_baseline(current, baseline)
    assert len(new_f) == 1
    assert new_f[0]["rule_id"] == "aws-access-key"
    assert len(persistent_f) == 1
    assert persistent_f[0]["rule_id"] == "python-sql-injection-format"
    assert len(fixed_f) == 0

def test_baseline_fixed_findings_detection():
    baseline = [
        {"rule_id": "python-sql-injection-format", "file_path": "app.py", "line": 3, "message": "SQL flaw"}
    ]
    current = [] # Fixed all issues!

    new_f, fixed_f, persistent_f = compare_findings_baseline(current, baseline)
    assert len(new_f) == 0
    assert len(persistent_f) == 0
    assert len(fixed_f) == 1
    assert fixed_f[0]["rule_id"] == "python-sql-injection-format"
