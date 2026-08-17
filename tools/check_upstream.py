#!/usr/bin/env python3
"""Record available upstream revisions without changing reviewed local bytes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "vendor" / "manifest.json"


def latest_commit(repo: str, path: str) -> str:
    query = urllib.parse.urlencode({"path": path, "per_page": 1})
    url = f"https://api.github.com/repos/{repo}/commits?{query}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "shadowrocket-config-updater/1"}
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        commits = json.load(response)
    if not commits or not isinstance(commits[0].get("sha"), str):
        raise RuntimeError(f"no commit returned for {repo}/{path}")
    return commits[0]["sha"]


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    changed = False
    for entry in manifest["scripts"] + manifest.get("derivedSources", []):
        available = latest_commit(entry["upstreamRepo"], entry["upstreamPath"])
        if entry.get("availableCommit") != available:
            entry["availableCommit"] = available
            changed = True
            print(f"update available: {entry['path']} {entry['reviewedCommit']} -> {available}")
        else:
            print(f"unchanged: {entry['path']}")
    if changed:
        MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
