#!/usr/bin/env python3
"""Synchronize approved Clash and sing-geosite data for Shadowrocket."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "rules" / "generated"
CACHE_DIR = ROOT / ".cache" / "sing-box"
CLASH_REPO = "Loyalsoldier/clash-rules"
CLASH_BRANCH = "release"
CLASH_NAMES = ("reject", "direct", "proxy", "private")
GEOSITE_REPO = "SagerNet/sing-geosite"
GEOSITE_BRANCH = "rule-set"
GEOSITE_NAMES = ("github", "apple", "icloud", "microsoft")
NAMES = CLASH_NAMES + GEOSITE_NAMES
SING_BOX_VERSION = "1.13.19"
SING_BOX_BASE_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SING_BOX_VERSION}/"
SING_BOX_ASSETS = (
    {
        "platform": "windows-amd64",
        "archive": "sing-box-1.13.19-windows-amd64.zip",
        "sha256": "e011a4def2f5e2b143ed54adb2b1a20a6be407806ab4442f3667f1dd817a2c8d",
        "executableMember": "sing-box-1.13.19-windows-amd64/sing-box.exe",
    },
    {
        "platform": "linux-amd64",
        "archive": "sing-box-1.13.19-linux-amd64.tar.gz",
        "sha256": "ef88a9e577d474210867bd708933d042e9b70106529df2656182c9db90106aa1",
        "executableMember": "sing-box-1.13.19-linux-amd64/sing-box",
    },
)
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 96 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
DOMAIN_RE = re.compile(r"(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)(?:\.(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?))*")
ENTRY_RE = re.compile(r"  - '([^']+)'\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
RULE_FIELDS = ("domain", "domain_suffix", "domain_keyword")


def request_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "shadowrocket-config-sync/1"}
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch(url: str, limit: int = MAX_SOURCE_BYTES) -> bytes:
    request = urllib.request.Request(url, headers=request_headers())
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"source exceeds {limit} bytes: {url}")
    return data


def latest_commit(repo: str, branch: str) -> str:
    try:
        data = json.loads(fetch(f"https://api.github.com/repos/{repo}/commits/{branch}", 1024 * 1024))
        commit = data.get("sha") if isinstance(data, dict) else None
    except urllib.error.HTTPError as error:
        if error.code not in (403, 429):
            raise
        feed = ET.fromstring(fetch(f"https://github.com/{repo}/commits/{branch}.atom", 1024 * 1024))
        entry_id = feed.findtext("{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}id", "")
        commit = entry_id.rsplit("/", 1)[-1]
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise ValueError(f"GitHub returned an invalid commit for {repo}:{branch}")
    return commit


def convert_payload(raw: bytes) -> list[str]:
    if raw.startswith(b"\xef\xbb\xbf") or b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        raise ValueError("payload must be UTF-8 without BOM/NUL/CR and end with LF")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("payload must contain ASCII only") from error
    lines = text.splitlines()
    if not lines or lines[0] != "payload:" or len(lines) == 1:
        raise ValueError("payload must start with 'payload:' and contain entries")

    output: list[str] = []
    seen: set[str] = set()
    for number, line in enumerate(lines[1:], 2):
        match = ENTRY_RE.fullmatch(line)
        if not match:
            raise ValueError(f"line {number}: unsupported payload syntax")
        value = match.group(1)
        suffix = value.startswith("+.")
        domain = value[2:] if suffix else value
        if len(domain) > 253 or not DOMAIN_RE.fullmatch(domain):
            raise ValueError(f"line {number}: unsupported domain {value!r}")
        converted = f".{domain}" if suffix else domain
        if converted not in seen:
            seen.add(converted)
            output.append(converted)
    return output


def _values(value: object, field: str, rule_number: int) -> list[str]:
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(item, str) or not item for item in values):
        raise ValueError(f"rule {rule_number}: {field} must be a nonempty string or list of nonempty strings")
    return values


def convert_geosite_json(raw: bytes) -> list[str]:
    if raw.startswith(b"\xef\xbb\xbf") or b"\x00" in raw:
        raise ValueError("decompiled source JSON must be UTF-8 without BOM or NUL")
    try:
        root = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("decompiled source is not valid UTF-8 JSON") from error
    if not isinstance(root, dict) or set(root) != {"version", "rules"}:
        raise ValueError("decompiled source root must contain only version and rules")
    if type(root["version"]) is not int or root["version"] != 1:
        raise ValueError("decompiled source version must be 1")
    rules = root["rules"]
    if not isinstance(rules, list) or not rules:
        raise ValueError("decompiled source rules must be a nonempty list")

    output: list[str] = []
    seen: set[str] = set()
    for rule_number, rule in enumerate(rules, 1):
        if not isinstance(rule, dict) or not rule or not set(rule) <= set(RULE_FIELDS):
            raise ValueError(f"rule {rule_number}: logical, unknown, or non-domain fields are forbidden")
        for field, prefix in (("domain", "DOMAIN"), ("domain_suffix", "DOMAIN-SUFFIX"), ("domain_keyword", "DOMAIN-KEYWORD")):
            if field not in rule:
                continue
            for value in _values(rule[field], field, rule_number):
                normalized = value[1:] if field == "domain_suffix" and value.startswith(".") else value
                if field != "domain_keyword":
                    if len(normalized) > 253 or not DOMAIN_RE.fullmatch(normalized):
                        raise ValueError(f"rule {rule_number}: invalid {field} value {value!r}")
                elif any(ord(char) < 33 or ord(char) > 126 for char in normalized) or "," in normalized:
                    raise ValueError(f"rule {rule_number}: unsafe domain_keyword value {value!r}")
                record = f"{prefix},{normalized}"
                if record not in seen:
                    seen.add(record)
                    output.append(record)
    if not output:
        raise ValueError("decompiled source contains no supported domain records")
    return output


def render_list(source_url: str, commit: str, records: list[str], tool_version: str | None = None) -> bytes:
    lines = [
        "# Generated by tools/sync_rules.py; do not edit.",
        f"# Source: {source_url}",
        f"# Commit: {commit}",
    ]
    if tool_version:
        lines.append(f"# Tool: SagerNet/sing-box {tool_version}")
    return ("\n".join([*lines, "", *records]) + "\n").encode("ascii")


def select_tool_asset(system: str | None = None, machine: str | None = None) -> dict[str, str]:
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    if machine not in {"amd64", "x86_64"}:
        raise ValueError(f"unsupported regeneration architecture: {machine}")
    target = f"{system}-amd64"
    for asset in SING_BOX_ASSETS:
        if asset["platform"] == target:
            return asset
    raise ValueError(f"unsupported regeneration host: {system}-{machine}")


def verify_digest(raw: bytes, expected: str, label: str) -> None:
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch for {label}: expected {expected}, got {actual}")


def _extract_executable(archive: bytes, asset: dict[str, str]) -> bytes:
    member_name = asset["executableMember"]
    member_path = PurePosixPath(member_name)
    if member_path.is_absolute() or ".." in member_path.parts:
        raise ValueError("unsafe executable archive member")
    try:
        if asset["archive"].endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                info = bundle.getinfo(member_name)
                if info.is_dir() or info.file_size > MAX_EXECUTABLE_BYTES:
                    raise ValueError("invalid executable archive member")
                executable = bundle.read(info)
        else:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
                info = bundle.getmember(member_name)
                if not info.isfile() or info.size > MAX_EXECUTABLE_BYTES:
                    raise ValueError("invalid executable archive member")
                source = bundle.extractfile(info)
                if source is None:
                    raise ValueError("missing executable archive member")
                executable = source.read(MAX_EXECUTABLE_BYTES + 1)
    except KeyError as error:
        raise ValueError(f"missing executable archive member: {member_name}") from error
    if not executable or len(executable) > MAX_EXECUTABLE_BYTES:
        raise ValueError("invalid executable archive member size")
    return executable


def verify_tool(executable: Path) -> None:
    checked = subprocess.run([str(executable), "version"], capture_output=True, text=True, timeout=15)
    output = checked.stdout + checked.stderr
    if checked.returncode or f"sing-box version {SING_BOX_VERSION}" not in output:
        raise ValueError(f"unexpected sing-box version output: {output.strip()!r}")


def ensure_converter() -> Path:
    asset = select_tool_asset()
    cache = CACHE_DIR / SING_BOX_VERSION
    archive_path = cache / asset["archive"]
    executable = cache / Path(asset["executableMember"]).name
    cache.mkdir(parents=True, exist_ok=True)
    if archive_path.is_file():
        if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError(f"cached archive exceeds {MAX_ARCHIVE_BYTES} bytes")
        archive = archive_path.read_bytes()
    else:
        archive = fetch(SING_BOX_BASE_URL + asset["archive"], MAX_ARCHIVE_BYTES)
    verify_digest(archive, asset["sha256"], asset["archive"])
    if not archive_path.is_file():
        archive_path.write_bytes(archive)
    expected_executable = _extract_executable(archive, asset)
    cache_matches = (
        executable.is_file()
        and executable.stat().st_size == len(expected_executable)
        and executable.read_bytes() == expected_executable
    )
    if not cache_matches:
        executable.write_bytes(expected_executable)
        executable.chmod(0o755)
    verify_tool(executable)
    return executable


def decompile_source(executable: Path, raw: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "source.srs"
        output = Path(temp) / "source.json"
        source.write_bytes(raw)
        checked = subprocess.run(
            [str(executable), "rule-set", "decompile", "-o", str(output), str(source)],
            capture_output=True, text=True, timeout=60,
        )
        if checked.returncode:
            raise ValueError(f"sing-box decompile failed: {(checked.stdout + checked.stderr).strip()}")
        if not output.is_file() or output.stat().st_size > MAX_JSON_BYTES:
            raise ValueError("sing-box produced missing or oversized JSON")
        return output.read_bytes()


def _file_entry(name: str, source_id: str, source_path: str, source_url: str, raw: bytes, rendered: bytes, records: list[str], rule_type: str) -> dict[str, object]:
    return {
        "name": name,
        "ruleType": rule_type,
        "sourceId": source_id,
        "sourcePath": source_path,
        "sourceUrl": source_url,
        "sourceSha256": hashlib.sha256(raw).hexdigest(),
        "outputSha256": hashlib.sha256(rendered).hexdigest(),
        "recordCount": len(records),
    }


def generate(clash_commit: str, geosite_commit: str) -> tuple[dict[str, bytes], bytes]:
    if not COMMIT_RE.fullmatch(clash_commit) or not COMMIT_RE.fullmatch(geosite_commit):
        raise ValueError("source commits must be full lowercase SHA-1 values")
    outputs: dict[str, bytes] = {}
    inventory: list[dict[str, object]] = []

    for name in CLASH_NAMES:
        source_path = f"{name}.txt"
        source_url = f"https://raw.githubusercontent.com/{CLASH_REPO}/{CLASH_BRANCH}/{source_path}"
        raw = fetch(f"https://raw.githubusercontent.com/{CLASH_REPO}/{clash_commit}/{source_path}")
        records = convert_payload(raw)
        rendered = render_list(source_url, clash_commit, records)
        outputs[f"{name}.list"] = rendered
        inventory.append(_file_entry(name, "clash-rules", source_path, source_url, raw, rendered, records, "DOMAIN-SET"))

    converter = ensure_converter()
    for name in GEOSITE_NAMES:
        source_path = f"geosite-{name}.srs"
        source_url = f"https://raw.githubusercontent.com/{GEOSITE_REPO}/{GEOSITE_BRANCH}/{source_path}"
        raw = fetch(f"https://raw.githubusercontent.com/{GEOSITE_REPO}/{geosite_commit}/{source_path}")
        records = convert_geosite_json(decompile_source(converter, raw))
        rendered = render_list(source_url, geosite_commit, records, SING_BOX_VERSION)
        outputs[f"{name}.list"] = rendered
        inventory.append(_file_entry(name, "sing-geosite", source_path, source_url, raw, rendered, records, "RULE-SET"))

    metadata = {
        "schemaVersion": 2,
        "sources": [
            {"id": "clash-rules", "repo": CLASH_REPO, "branch": CLASH_BRANCH, "commit": clash_commit},
            {"id": "sing-geosite", "repo": GEOSITE_REPO, "branch": GEOSITE_BRANCH, "commit": geosite_commit},
        ],
        "tool": {
            "repo": "SagerNet/sing-box",
            "version": SING_BOX_VERSION,
            "baseUrl": SING_BOX_BASE_URL,
            "assets": list(SING_BOX_ASSETS),
        },
        "files": inventory,
    }
    return outputs, (json.dumps(metadata, indent=2) + "\n").encode("ascii")


def write_or_check(outputs: dict[str, bytes], metadata: bytes, check: bool) -> bool:
    expected = {**outputs, "metadata.json": metadata}
    actual_names = {path.name for path in OUTPUT_DIR.iterdir()} if OUTPUT_DIR.is_dir() else set()
    stale = actual_names != set(expected)
    stale_names: list[str] = []
    for name, content in expected.items():
        path = OUTPUT_DIR / name
        if not path.is_file() or path.read_bytes() != content:
            stale = True
            stale_names.append(name)
    if check:
        if stale:
            print(f"generated rules are stale: {', '.join(stale_names) or 'unexpected inventory'}", file=sys.stderr)
            return False
        print("generated rule check passed")
        return True
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for path in OUTPUT_DIR.iterdir():
        if path.is_file() and path.name not in expected:
            path.unlink()
    for name, content in expected.items():
        (OUTPUT_DIR / name).write_bytes(content)
    source_data = json.loads(metadata)["sources"]
    print(f"generated {len(outputs)} rule sets at clash {source_data[0]['commit']} and geosite {source_data[1]['commit']}")
    return True


def pinned_commits() -> tuple[str, str]:
    metadata = json.loads((OUTPUT_DIR / "metadata.json").read_text(encoding="ascii"))
    sources = metadata.get("sources")
    if not isinstance(sources, list):
        raise ValueError("generated metadata has no source inventory")
    commits = {
        source.get("id"): source.get("commit")
        for source in sources
        if isinstance(source, dict)
    }
    clash_commit = commits.get("clash-rules")
    geosite_commit = commits.get("sing-geosite")
    if not isinstance(clash_commit, str) or not COMMIT_RE.fullmatch(clash_commit):
        raise ValueError("generated metadata has an invalid clash-rules commit")
    if not isinstance(geosite_commit, str) or not COMMIT_RE.fullmatch(geosite_commit):
        raise ValueError("generated metadata has an invalid sing-geosite commit")
    return clash_commit, geosite_commit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated output differs from regenerated data")
    parser.add_argument("--pinned", action="store_true", help="regenerate from commits recorded in metadata (requires --check)")
    parser.add_argument("--clash-commit", help="use an exact clash-rules release commit")
    parser.add_argument("--geosite-commit", help="use an exact sing-geosite rule-set commit")
    args = parser.parse_args()
    if args.pinned and not args.check:
        parser.error("--pinned requires --check")
    if args.pinned and (args.clash_commit or args.geosite_commit):
        parser.error("--pinned cannot be combined with explicit commits")
    try:
        if args.pinned:
            clash_commit, geosite_commit = pinned_commits()
        else:
            clash_commit = args.clash_commit or latest_commit(CLASH_REPO, CLASH_BRANCH)
            geosite_commit = args.geosite_commit or latest_commit(GEOSITE_REPO, GEOSITE_BRANCH)
        outputs, metadata = generate(clash_commit, geosite_commit)
        return 0 if write_or_check(outputs, metadata, args.check) else 1
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"rule sync failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
