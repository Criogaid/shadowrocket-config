#!/usr/bin/env python3
"""Online validation of complete route payloads and exact provenance objects."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import urllib.request

from sync_rules import CLASH_NAMES, convert_payload, NAMES

ROOT = Path(__file__).resolve().parents[1]
MAX_ROUTE_BYTES = 8 * 1024 * 1024


def fetch(url: str, limit: int) -> bytes:
    headers = {"User-Agent": "shadowrocket-config-validator/1"}
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"remote object exceeds {limit} bytes: {url}")
    return data


def validate_geoip(name: str, raw: bytes) -> int:
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if b"\r" in raw or b"\x00" in raw or not raw.endswith(b"\n"):
        raise ValueError(f"geoip {name}: invalid encoding/line endings")
    text = raw.decode("ascii", errors="strict")
    count = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(IP-CIDR6?),([^,]+)", line)
        if not match:
            raise ValueError(f"geoip {name}:{number}: invalid record")
        network = ipaddress.ip_network(match.group(2), strict=True)
        expected = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
        if match.group(1) != expected:
            raise ValueError(f"geoip {name}:{number}: address family mismatch")
        count += 1
    if not count:
        raise ValueError(f"geoip {name}: empty data")
    return count


def validate_generated_sources() -> None:
    metadata = json.loads((ROOT / "rules" / "generated" / "metadata.json").read_text(encoding="ascii"))
    sources = {source["id"]: source for source in metadata["sources"]}
    entries = metadata["files"]
    if [entry["name"] for entry in entries] != list(NAMES):
        raise ValueError("generated metadata inventory mismatch")
    for entry in entries:
        source = sources[entry["sourceId"]]
        url = f"https://raw.githubusercontent.com/{source['repo']}/{source['commit']}/{entry['sourcePath']}"
        raw = fetch(url, MAX_ROUTE_BYTES)
        if hashlib.sha256(raw).hexdigest() != entry["sourceSha256"]:
            raise ValueError(f"generated source hash mismatch: {entry['name']}")
        if entry["name"] in CLASH_NAMES:
            records = convert_payload(raw)
            if len(records) != entry["recordCount"]:
                raise ValueError(f"generated source count mismatch: {entry['name']}")
            detail = f"{len(records)} records"
        else:
            detail = f"{len(raw)} pinned SRS bytes"
        print(f"remote {entry['sourceId']} {entry['name']}: ok ({detail}, commit {source['commit']})")


def validate_geoip_sources() -> None:
    for name in ("private", "cn"):
        url = f"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/surge/{name}.txt"
        count = validate_geoip(name, fetch(url, MAX_ROUTE_BYTES))
        print(f"remote geoip {name}: ok ({count} CIDRs)")


def validate_provenance() -> None:
    manifest = json.loads((ROOT / "vendor" / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["scripts"] + manifest.get("derivedSources", []):
        url = f"https://raw.githubusercontent.com/{entry['upstreamRepo']}/{entry['reviewedCommit']}/{entry['upstreamPath']}"
        raw = fetch(url, 2 * 1024 * 1024)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != entry["upstreamSha256"]:
            raise ValueError(f"provenance hash mismatch: {entry['path']}")
        print(f"provenance {entry['path']}: ok ({entry['reviewedCommit']}, {digest})")


def main() -> int:
    try:
        validate_generated_sources()
        validate_geoip_sources()
        validate_provenance()
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        print(f"remote validation failed: {error}")
        return 1
    print("remote validation passed: complete Clash/GeoIP records and exact pinned provenance hashes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
