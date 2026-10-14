"""Verify the TRIDENT repo: files present, no giant blobs, commits authored correctly.

Run from repo root:
    python tools/verify_repo.py
    python tools/verify_repo.py --remote   # also checks github.com/aalok101singh/trident
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
from pathlib import Path


REPO_ID = "aalok101singh/trident"
MAX_TRACKED_BYTES = 5_000_000  # 5 MB per file — nothing legit is bigger

# --- what the repo is expected to contain -----------------------------

REQUIRED_TRACKED = [
    # top-level
    ".gitignore",
    "LICENSE",
    "LICENSE-MODEL",
    "Makefile",
    "README.md",
    "cleanup_template.ps1",
    "requirements.txt",
    "simulate_threat.ps1",
    "strings.json",
    "trident.toml",
    "MODEL_CARD.md",
    # package
    "trident/__init__.py",
    "trident/__main__.py",
    "trident/action.py",
    "trident/audit.py",
    "trident/cascade.py",
    "trident/config.py",
    "trident/contracts.py",
    "trident/decision.py",
    "trident/report.py",
    "trident/system_defaults.py",
    "trident/telemetry.py",
    "trident/toast.py",
    "trident/trust_store.py",
    "trident/ui.py",
    "trident/setup/__init__.py",
    "trident/setup/download_model.py",
    # models (small JSON only)
    "models/rl_agent_config.json",
    "models/tokenizer.json",
    "models/tokenizer_config.json",
]

FORBIDDEN_TRACKED_PATTERNS = [
    ".onnx",
    ".onnx.data",
    ".safetensors",
    "/.venv/",
    "/venv/",
    "/logs/",
    "/dist/",
    "/build/",
    "/hf_upload/",
    "/config/trusted_paths.json",
    "__pycache__",
    ".pyc",
    ".spec",
]

EXPECTED_COMMITS = 8
EXPECTED_AUTHORS = {"Aalok Singh", "Pravin Kumar"}


# --- helpers ----------------------------------------------------------

def _run(cmd: list[str], check: bool = True) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\n{r.stderr}")
    return r.stdout


def _tracked_files() -> list[str]:
    out = _run(["git", "ls-files"])
    return [line.strip() for line in out.splitlines() if line.strip()]


def _file_size(path: str) -> int:
    try:
        return Path(path).stat().st_size
    except OSError:
        return -1


def _commit_summary() -> list[tuple[str, str, str, list[str]]]:
    """Return [(hash, author_name, subject, co_authors), ...] oldest→newest."""
    fmt = "%H%x1f%an%x1f%s%x1f%(trailers:key=Co-authored-by,valueonly)%x1e"
    out = _run(["git", "log", f"--format={fmt}"])
    commits = []
    for chunk in out.split("\x1e"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split("\x1f")
        if len(parts) < 4:
            continue
        h, author, subject, co_raw = parts[0], parts[1], parts[2], parts[3]
        co = [line.strip() for line in co_raw.splitlines() if line.strip()]
        commits.append((h, author, subject, co))
    return list(reversed(commits))


# --- checks -----------------------------------------------------------

def check_files() -> int:
    print("── tracked files ──")
    tracked = set(_tracked_files())
    fails = 0

    missing = [p for p in REQUIRED_TRACKED if p not in tracked]
    if missing:
        print(f"  FAIL: {len(missing)} required file(s) missing from index:")
        for p in missing:
            print(f"        {p}")
        fails += len(missing)
    else:
        print(f"  OK: all {len(REQUIRED_TRACKED)} required files present")

    forbidden = []
    for path in tracked:
        for pat in FORBIDDEN_TRACKED_PATTERNS:
            if pat in path or path.endswith(pat):
                forbidden.append(path)
                break
    if forbidden:
        print(f"  FAIL: {len(forbidden)} forbidden file(s) tracked:")
        for p in forbidden:
            print(f"        {p}")
        fails += len(forbidden)
    else:
        print("  OK: no forbidden paths tracked")

    big = [(p, _file_size(p)) for p in tracked if _file_size(p) > MAX_TRACKED_BYTES]
    if big:
        print(f"  FAIL: {len(big)} file(s) over {MAX_TRACKED_BYTES//1_000_000} MB:")
        for p, sz in big:
            print(f"        {p} ({sz/1_000_000:.1f} MB)")
        fails += len(big)
    else:
        print(f"  OK: no tracked file over {MAX_TRACKED_BYTES//1_000_000} MB")

    print(f"  total tracked files: {len(tracked)}")
    return fails


def check_commits() -> int:
    print("\n── commits ──")
    commits = _commit_summary()
    fails = 0

    print(f"  local commit count: {len(commits)}")
    if len(commits) < EXPECTED_COMMITS:
        print(f"  WARN: expected at least {EXPECTED_COMMITS} commits (incl. the initial README)")

    seen_authors = set()
    no_coauthor = []
    wrong_author = []
    for h, author, subject, co in commits:
        seen_authors.add(author)
        if author not in EXPECTED_AUTHORS:
            wrong_author.append((h, author, subject))
        # every commit in the TRIDENT series should have a co-author trailer
        if "Commit README.md" not in subject and not co:
            no_coauthor.append((h, author, subject))

    if wrong_author:
        print(f"  FAIL: {len(wrong_author)} commit(s) with unexpected author:")
        for h, a, s in wrong_author:
            print(f"        {h[:7]}  {a}  —  {s}")
        fails += len(wrong_author)
    else:
        print(f"  OK: all commits authored by {sorted(seen_authors)}")

    if no_coauthor:
        print(f"  FAIL: {len(no_coauthor)} commit(s) missing Co-authored-by trailer:")
        for h, a, s in no_coauthor:
            print(f"        {h[:7]}  {a}  —  {s}")
        fails += len(no_coauthor)
    else:
        print("  OK: every substantive commit has a co-author")

    # alternating check
    series = [c for c in commits if "Commit README.md" not in c[2]]
    authors_seq = [c[1] for c in series]
    alternates = all(authors_seq[i] != authors_seq[i+1] for i in range(len(authors_seq) - 1))
    print(f"  OK: alternate authorship" if alternates else "  WARN: authors are not strictly alternating")

    return fails


def check_remote() -> int:
    print(f"\n── remote {REPO_ID} ──")
    fails = 0
    try:
        url = f"https://api.github.com/repos/{REPO_ID}"
        with urllib.request.urlopen(url, timeout=10) as r:
            meta = json.load(r)
    except Exception as e:
        print(f"  FAIL: cannot reach GitHub API: {e}")
        return 1

    print(f"  size:  {meta.get('size', '?')} KB")
    print(f"  stars: {meta.get('stargazers_count', 0)}")
    print(f"  url:   {meta.get('html_url')}")

    # list top-level tree
    try:
        url = f"https://api.github.com/repos/{REPO_ID}/git/trees/{meta['default_branch']}?recursive=1"
        with urllib.request.urlopen(url, timeout=15) as r:
            tree = json.load(r)
    except Exception as e:
        print(f"  FAIL: cannot fetch tree: {e}")
        return fails + 1

    paths = [item["path"] for item in tree.get("tree", []) if item.get("type") == "blob"]
    print(f"  tracked files on remote: {len(paths)}")

    if meta.get("size", 0) > 20_000_000:
        print("  FAIL: remote repo over 20 GB -- big file was pushed")
        fails += 1
    else:
        print("  OK: remote repo size is reasonable")

    # quick sanity: the critical modules must exist
    critical = ["trident/decision.py", "trident/cascade.py", "trident/__main__.py", "trident/toast.py"]
    missing = [p for p in critical if p not in paths]
    if missing:
        print(f"  FAIL: missing on remote: {missing}")
        fails += len(missing)
    else:
        print("  OK: critical modules present on remote")

    return fails


# --- main -------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--remote", action="store_true", help="also check the GitHub remote")
    args = ap.parse_args()

    fails = 0
    fails += check_files()
    fails += check_commits()
    if args.remote:
        fails += check_remote()

    print("\n" + ("=" * 40))
    if fails == 0:
        print("RESULT: PASS")
        return 0
    print(f"RESULT: FAIL ({fails} issue{'s' if fails != 1 else ''})")
    return 1


if __name__ == "__main__":
    sys.exit(main())