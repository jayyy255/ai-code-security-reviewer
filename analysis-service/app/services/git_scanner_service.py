import os
import shutil
import tempfile
import git
from pathlib import Path
from pydantic import BaseModel, Field

DEPENDENCY_LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
    "pipfile.lock", "poetry.lock", "go.sum", "cargo.lock", "pom.xml", "build.gradle"
}

SECURITY_CONFIG_FILES = {
    ".semgrep.yml", ".semgrep.yaml", ".gitleaks.toml", ".snyk", "security.md"
}

class GitScanTarget(BaseModel):
    repository_url: str
    commit_sha: str | None = None
    branch: str | None = None
    strategy: str = "auto" # "auto", "full", "incremental"
    baseline_findings: list[dict] = Field(default_factory=list)

class GitDiffSummary(BaseModel):
    added_files: list[str] = Field(default_factory=list)
    modified_files: list[str] = Field(default_factory=list)
    renamed_files: list[str] = Field(default_factory=list)
    deleted_files: list[str] = Field(default_factory=list)
    is_merge_commit: bool = False
    lockfile_changed: bool = False
    security_config_changed: bool = False
    large_change_ratio: bool = False
    force_full_reason: str | None = None

def clone_and_resolve_git(repo_url: str, target_commit: str | None = None, branch: str | None = None, dest_dir: str = "") -> tuple[git.Repo, str, str | None]:
    """
    Clones the target repository and checks out the specific commit or branch.
    Returns (repo_obj, commit_sha, parent_sha).
    """
    clone_kwargs = {}
    if branch and not target_commit:
        clone_kwargs["branch"] = branch

    # Isolated clone
    repo = git.Repo.clone_from(repo_url, dest_dir, **clone_kwargs)

    if target_commit:
        repo.git.checkout(target_commit)
    elif branch:
        repo.git.checkout(branch)

    head_commit = repo.head.commit
    commit_sha = head_commit.hexsha
    parent_sha = head_commit.parents[0].hexsha if head_commit.parents else None

    return repo, commit_sha, parent_sha

def analyze_git_diff(repo: git.Repo, commit_sha: str, parent_sha: str | None) -> GitDiffSummary:
    """
    Analyzes the commit diff against its parent commit to classify changed files
    and evaluate full scan triggers.
    """
    commit = repo.commit(commit_sha)

    if not parent_sha or len(commit.parents) == 0:
        return GitDiffSummary(force_full_reason="No parent commit available (Initial commit).")

    if len(commit.parents) > 1:
        return GitDiffSummary(is_merge_commit=True, force_full_reason="Merge commit detected with multiple parents.")

    parent = repo.commit(parent_sha)
    diff_index = parent.diff(commit)

    added = []
    modified = []
    renamed = []
    deleted = []
    lockfile_changed = False
    security_config_changed = False

    for diff_item in diff_index:
        path = diff_item.b_path or diff_item.a_path
        base_name = os.path.basename(path).lower()

        if base_name in DEPENDENCY_LOCKFILES:
            lockfile_changed = True
        if base_name in SECURITY_CONFIG_FILES or ".semgrep" in path.lower():
            security_config_changed = True

        if diff_item.change_type == 'A':
            added.append(path)
        elif diff_item.change_type == 'M':
            modified.append(path)
        elif diff_item.change_type == 'R':
            renamed.append(path)
        elif diff_item.change_type == 'D':
            deleted.append(path)

    # Check total files in tree to determine ratio
    all_files = [item.path for item in commit.tree.traverse() if item.type == 'blob']
    total_files_count = len(all_files) or 1
    large_change_ratio = total_files_count >= 10 and (total_changed / total_files_count) > 0.30

    force_reason = None
    if lockfile_changed:
        force_reason = "Dependency lockfile modified (package-lock.json, requirements.txt, etc.)."
    elif security_config_changed:
        force_reason = "Security rules or repository scanner configuration changed."
    elif large_change_ratio:
        force_reason = f"Large change ratio detected ({total_changed}/{total_files_count} files changed)."

    return GitDiffSummary(
        added_files=added,
        modified_files=modified,
        renamed_files=renamed,
        deleted_files=deleted,
        is_merge_commit=False,
        lockfile_changed=lockfile_changed,
        security_config_changed=security_config_changed,
        large_change_ratio=large_change_ratio,
        force_full_reason=force_reason
    )

def compare_findings_baseline(current_findings: list[dict], baseline_findings: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Compares current scan findings with previous baseline findings.
    Returns (new_findings, fixed_findings, persistent_findings).
    """
    if not baseline_findings:
        return current_findings, [], []

    def finding_key(f):
        return (
            f.get("rule_id", ""),
            f.get("file_path", "").replace("\\", "/"),
            f.get("line")
        )

    def finding_rule_file(f):
        return (
            f.get("rule_id", ""),
            f.get("file_path", "").replace("\\", "/")
        )

    current_keys = {finding_key(f): f for f in current_findings}
    baseline_keys = {finding_key(f): f for f in baseline_findings}

    current_rule_files = {finding_rule_file(f): f for f in current_findings}
    baseline_rule_files = {finding_rule_file(f): f for f in baseline_findings}

    new_findings = []
    persistent_findings = []

    for curr in current_findings:
        ck = finding_key(curr)
        crf = finding_rule_file(curr)
        if ck in baseline_keys or crf in baseline_rule_files:
            persistent_findings.append(curr)
        else:
            new_findings.append(curr)

    fixed_findings = []
    for base in baseline_findings:
        bk = finding_key(base)
        brf = finding_rule_file(base)
        if bk not in current_keys and brf not in current_rule_files:
            fixed_findings.append(base)

    return new_findings, fixed_findings, persistent_findings
