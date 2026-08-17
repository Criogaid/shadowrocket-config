#!/usr/bin/env python3
"""Fail-closed validation for configuration, generated data, scripts, and workflows."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlparse

from sync_rules import (
    CLASH_BRANCH, CLASH_NAMES, CLASH_REPO, COMMIT_RE, DOMAIN_RE, GEOSITE_BRANCH,
    GEOSITE_NAMES, GEOSITE_REPO, NAMES, SING_BOX_ASSETS, SING_BOX_BASE_URL,
    SING_BOX_VERSION,
)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "shadowrocket.conf"
MANIFEST = ROOT / "vendor" / "manifest.json"
SCRIPT_ROOT = (ROOT / "vendor" / "scripts").resolve()
GENERATED = ROOT / "rules" / "generated"
OWN_RAW_PREFIX = "https://raw.githubusercontent.com/Criogaid/shadowrocket-config/main/"
SCRIPT_PATH = "vendor/scripts/bilibili-ads.js"
SCRIPT_RUNTIME_COMMIT = "9b925153cffcc243d9e8625f8e8ae43e03d9c410"
TRIGGER_HOST = "app.bilibili.com"
TRIGGER_PATH = r"^/x/v2/(?:splash/(?:list|show)|feed/index)(?:\?|$)"
SCRIPT_LINE = (
    r"bilibili-ads = type=http-response,pattern=^https://app\.bilibili\.com/x/v2/"
    r"(?:splash/(?:list|show)|feed/index)(?:\?|$),requires-body=1,max-size=0,"
    f"script-path=https://raw.githubusercontent.com/Criogaid/shadowrocket-config/{SCRIPT_RUNTIME_COMMIT}/{SCRIPT_PATH},"
    "script-update-interval=0"
)
GENERATED_RULES = {
    name: f"{'RULE-SET' if name in GEOSITE_NAMES else 'DOMAIN-SET'},{OWN_RAW_PREFIX}rules/generated/{name}.list,"
    + ("REJECT" if name == "reject" else "PROXY" if name in ("proxy", "github") else "DIRECT")
    for name in NAMES
}
ROUTE_TAIL = [
    GENERATED_RULES["reject"],
    GENERATED_RULES["github"],
    GENERATED_RULES["apple"],
    GENERATED_RULES["icloud"],
    GENERATED_RULES["microsoft"],
    GENERATED_RULES["private"],
    GENERATED_RULES["proxy"],
    GENERATED_RULES["direct"],
    "RULE-SET,https://raw.githubusercontent.com/Loyalsoldier/geoip/release/surge/private.txt,DIRECT",
    "RULE-SET,https://raw.githubusercontent.com/Loyalsoldier/geoip/release/surge/cn.txt,DIRECT",
    "FINAL,PROXY",
]
HANDWRITTEN_SERVICE_SUFFIXES = {
    "github.com", "githubusercontent.com", "githubassets.com", "apple.com", "icloud.com",
    "microsoft.com", "microsoftonline.com", "microsoftonline-p.com",
    "microsoftazuread-sso.com", "msauth.net", "msftauth.net", "office.com",
    "office.net", "office365.com", "onedrive.com", "1drv.com", "1drv.ms", "live.com",
    "live.net", "outlook.com", "sharepoint.com", "sharepointonline.com", "windows.net",
}
MITM_HOSTS = (
    "*.amemv.com", "acs.m.taobao.com", "api.m.jd.com", "api.pinduoduo.com",
    "api.yangkeduo.com", "api.zhihu.com", "app.bilibili.com", "az2-api.ksapisrv.com",
    "bdsp-x.jd.com", "ccsp-egmas.sf-express.com", "ci.xiaohongshu.com",
    "cn-acs.m.cainiao.com", "dsp-x.jd.com", "elemecdn.com", "guide-acs.m.taobao.com",
    "hd.xiaojukeji.com", "interface.music.163.com", "interface3.music.163.com",
    "ipv4.music.163.com", "m5.amap.com", "ma-adx.ctrip.com", "mapi.dianping.com",
    "newclient.map.baidu.com", "optimus-ads.amap.com", "wmapi.meituan.com",
    "www.xiaohongshu.com", "y.gtimg.cn",
)
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
FORBIDDEN_SCRIPT_PATTERNS = {
    "outbound HTTP": r"\$httpClient|\$task|\bfetch\s*\(|XMLHttpRequest|WebSocket",
    "persistence": r"\$persistentStore|\$prefs|localStorage|sessionStorage",
    "request secrets": r"\$request\.(?:headers|body)",
    "dynamic code": r"\beval\s*\(|\bFunction\s*\(|\brequire\s*\(|\bimport\s*(?:\(|\s)",
    "runtime process": r"child_process|\bprocess\.|module\.exports",
    "credential/account capability": r"authorization|cookie|set-cookie|password|token|session|credential|login|signin|checkin|redeem|exchange|lottery|withdraw|account|deviceid",
    "paid entitlement capability": r"\bvip\b|svip|premium|paywall|purchase|subscription|subscriber|entitlement|revenuecat|unlock|expire|playright|downright|ispaid",
    "timer": r"setTimeout|setInterval",
    "remote executable": r"https?://|raw\.githubusercontent\.com|gist\.githubusercontent\.com|script-path",
}


def fail(message: str) -> None:
    raise ValueError(message)


def sections(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = re.fullmatch(r"\[([^]]+)]", line.strip())
        if match:
            current = match.group(1)
            result.setdefault(current, [])
        elif current is not None:
            result[current].append(line)
    return result


def data_lines(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def validate_custom(lines: list[str]) -> None:
    domain_rule = re.compile(r"(DOMAIN(?:-SUFFIX)?),([^,]+),(DIRECT|PROXY|REJECT)")
    cidr_rule = re.compile(r"(IP-CIDR6?),([^,]+),(DIRECT|PROXY|REJECT)(?:,no-resolve)?")
    for line in lines:
        if match := domain_rule.fullmatch(line):
            if not DOMAIN_RE.fullmatch(match.group(2)):
                fail(f"invalid custom domain rule: {line}")
        elif match := cidr_rule.fullmatch(line):
            try:
                network = ipaddress.ip_network(match.group(2), strict=False)
            except ValueError:
                fail(f"invalid custom CIDR rule: {line}")
            expected = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
            if match.group(1) != expected:
                fail(f"custom CIDR address family mismatch: {line}")
        else:
            fail(f"unsupported custom rule syntax: {line}")


def validate_config(text: str) -> None:
    parsed = sections(text)
    for required in ("General", "Rule", "Script", "MITM"):
        if len(re.findall(rf"(?m)^\[{re.escape(required)}]$", text)) != 1:
            fail(f"expected exactly one [{required}] section")
    if "Proxy" in parsed or "Proxy Group" in parsed:
        fail("custom proxy sections are forbidden; use built-in PROXY")

    general = data_lines(parsed["General"])
    required_settings = {
        "ipv6 = true", "prefer-ipv6 = false", "private-ip-answer = true",
        "stun-response-ip = 1.1.1.1", "stun-response-ipv6 = ::1", "block-quic = all-proxy",
        f"update-url = {OWN_RAW_PREFIX}dist/shadowrocket.conf",
    }
    if missing := sorted(required_settings - set(general)):
        fail(f"missing required general settings: {missing}")
    expected_doh = "https://dns.quad9.net/dns-query#proxy,https://cloudflare-dns.com/dns-query#proxy"
    if f"dns-server = {expected_doh}" not in general or f"fallback-dns-server = {expected_doh}" not in general:
        fail("Quad9 and Cloudflare DoH must use the documented #proxy fragment")
    if "direct-dns-server = https://dns.alidns.com/dns-query,https://doh.pub/dns-query" not in general:
        fail("direct DNS must use AliDNS and DNSPod")
    if "proxy-dns-server = 223.5.5.5,119.29.29.29" not in general:
        fail("proxy DNS must retain domestic bootstrap resolvers")

    custom = data_lines((ROOT / "rules" / "custom.list").read_text(encoding="utf-8").splitlines())
    apps = data_lines((ROOT / "rewrites" / "apps.list").read_text(encoding="utf-8").splitlines())
    validate_custom(custom)
    if any(not line.startswith(("DOMAIN,", "DOMAIN-SUFFIX,", "URL-REGEX,")) for line in apps):
        fail("unsupported curated app rule syntax")
    if re.search(r"cupid\.iqiyi|youku\.play|boot(?:preload|realtime).*weibo", "\n".join(apps), re.IGNORECASE):
        fail("unsafe or unproven iQIYI/Youku/Weibo rule found")
    rules = data_lines(parsed["Rule"])
    if rules != custom + apps + ROUTE_TAIL:
        fail("route rules differ from the approved inventory or order")
    if "v2ray-rules-dat" in text:
        fail("V2Ray domain lists cannot be used as Shadowrocket DOMAIN-SET input")
    for rule in rules:
        match = re.fullmatch(r"DOMAIN(?:-SUFFIX)?,([^,]+),(?:DIRECT|PROXY|REJECT)", rule)
        if match and match.group(1) in HANDWRITTEN_SERVICE_SUFFIXES:
            fail(f"handwritten service fallback rule is forbidden: {rule}")
    for rule in rules:
        if rule.startswith(("DOMAIN-SET,", "RULE-SET,")):
            url = rule.split(",", 2)[1]
            parsed_url = urlparse(url)
            if parsed_url.hostname != "raw.githubusercontent.com":
                fail(f"unapproved remote route host: {url}")

    if data_lines(parsed["Script"]) != [SCRIPT_LINE]:
        fail("Script declaration differs from the reviewed manifest binding")
    if data_lines(parsed["MITM"]) != ["h2 = true", f"hostname = {','.join(MITM_HOSTS)}"]:
        fail("MITM must use exact h2 and approved hostname inventory")


def _rule_set_covers(records: list[str], target: str) -> bool:
    for record in records:
        kind, value = record.split(",", 1)
        if kind == "DOMAIN" and value == target:
            return True
        if kind == "DOMAIN-SUFFIX" and (value == target or target.endswith(f".{value}")):
            return True
        if kind == "DOMAIN-KEYWORD" and value in target:
            return True
    return False


def validate_generated() -> None:
    expected_names = {*(f"{name}.list" for name in NAMES), "metadata.json"}
    actual_names = {path.name for path in GENERATED.iterdir() if path.is_file()}
    if actual_names != expected_names:
        fail(f"generated inventory mismatch: {sorted(actual_names)}")
    metadata = json.loads((GENERATED / "metadata.json").read_text(encoding="ascii"))
    if set(metadata) != {"schemaVersion", "sources", "tool", "files"} or metadata.get("schemaVersion") != 2:
        fail("invalid generated metadata root")
    sources = metadata.get("sources")
    expected_sources = [
        {"id": "clash-rules", "repo": CLASH_REPO, "branch": CLASH_BRANCH},
        {"id": "sing-geosite", "repo": GEOSITE_REPO, "branch": GEOSITE_BRANCH},
    ]
    if not isinstance(sources, list) or len(sources) != 2:
        fail("invalid generated source inventory")
    commits: dict[str, str] = {}
    for source, expected in zip(sources, expected_sources, strict=True):
        if not isinstance(source, dict) or set(source) != {*expected, "commit"}:
            fail("invalid generated source schema")
        if any(source[key] != value for key, value in expected.items()):
            fail("invalid generated source ownership")
        if not isinstance(source["commit"], str) or not COMMIT_RE.fullmatch(source["commit"]):
            fail("invalid generated source commit")
        commits[source["id"]] = source["commit"]
    expected_tool = {
        "repo": "SagerNet/sing-box",
        "version": SING_BOX_VERSION,
        "baseUrl": SING_BOX_BASE_URL,
        "assets": list(SING_BOX_ASSETS),
    }
    if metadata.get("tool") != expected_tool:
        fail("invalid pinned sing-box tool metadata")

    entries = metadata.get("files")
    if not isinstance(entries, list) or [entry.get("name") for entry in entries if isinstance(entry, dict)] != list(NAMES):
        fail("generated metadata file order/inventory mismatch")
    representative_records: dict[str, list[str]] = {}
    entry_keys = {"name", "ruleType", "sourceId", "sourcePath", "sourceUrl", "sourceSha256", "outputSha256", "recordCount"}
    for entry in entries:
        if set(entry) != entry_keys:
            fail(f"generated {entry.get('name')} metadata schema mismatch")
        name = entry["name"]
        is_geosite = name in GEOSITE_NAMES
        source_id = "sing-geosite" if is_geosite else "clash-rules"
        branch = GEOSITE_BRANCH if is_geosite else CLASH_BRANCH
        repo = GEOSITE_REPO if is_geosite else CLASH_REPO
        source_path = f"geosite-{name}.srs" if is_geosite else f"{name}.txt"
        source_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{source_path}"
        path = GENERATED / f"{name}.list"
        raw = path.read_bytes()
        if b"\r" in raw or b"\x00" in raw or not raw.endswith(b"\n"):
            fail(f"generated {name} must be ASCII/LF with a final newline")
        try:
            lines = raw.decode("ascii", errors="strict").splitlines()
        except UnicodeDecodeError as error:
            fail(f"generated {name} is not ASCII: {error}")
        header = [
            "# Generated by tools/sync_rules.py; do not edit.",
            f"# Source: {source_url}",
            f"# Commit: {commits[source_id]}",
        ]
        if is_geosite:
            header.append(f"# Tool: SagerNet/sing-box {SING_BOX_VERSION}")
        header.append("")
        if lines[:len(header)] != header:
            fail(f"generated {name} header mismatch")
        records = lines[len(header):]
        if not records or len(records) != len(set(records)):
            fail(f"generated {name} is empty or contains duplicates")
        for number, value in enumerate(records, len(header) + 1):
            if is_geosite:
                match = re.fullmatch(r"(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD),([^,]+)", value)
                if not match:
                    fail(f"generated {name}:{number}: invalid RULE-SET record")
                if match.group(1) == "DOMAIN-KEYWORD":
                    if any(ord(char) < 33 or ord(char) > 126 for char in match.group(2)):
                        fail(f"generated {name}:{number}: unsafe RULE-SET keyword")
                elif len(match.group(2)) > 253 or not DOMAIN_RE.fullmatch(match.group(2)):
                    fail(f"generated {name}:{number}: invalid RULE-SET domain")
            else:
                domain = value[1:] if value.startswith(".") else value
                if not domain or len(domain) > 253 or not DOMAIN_RE.fullmatch(domain):
                    fail(f"generated {name}:{number}: invalid DOMAIN-SET record")
        expected_type = "RULE-SET" if is_geosite else "DOMAIN-SET"
        if entry["ruleType"] != expected_type or entry["sourceId"] != source_id or entry["sourcePath"] != source_path:
            fail(f"generated {name} ownership metadata mismatch")
        if entry["sourceUrl"] != source_url or entry["recordCount"] != len(records):
            fail(f"generated {name} metadata mismatch")
        if not re.fullmatch(r"[0-9a-f]{64}", str(entry["sourceSha256"])):
            fail(f"generated {name} source hash is invalid")
        if entry["outputSha256"] != hashlib.sha256(raw).hexdigest():
            fail(f"generated {name} output hash mismatch")
        if is_geosite:
            representative_records[name] = records

    required_coverage = {
        "apple": ("apps.mzstatic.com",),
        "icloud": ("icloud.com",),
        "github": ("github.com", "githubusercontent.com"),
    }
    for name, domains in required_coverage.items():
        for domain in domains:
            if not _rule_set_covers(representative_records[name], domain):
                fail(f"generated {name} lacks required coverage for {domain}")
    if not any(_rule_set_covers(representative_records["microsoft"], domain) for domain in ("live.com", "office.net")):
        fail("generated microsoft lacks required live.com/office.net coverage")


def validate_vendor() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = manifest.get("scripts")
    if manifest.get("schemaVersion") != 1 or not isinstance(entries, list):
        fail("invalid vendor manifest schema")
    actual = {path.resolve() for path in SCRIPT_ROOT.rglob("*.js")}
    listed: set[Path] = set()
    required = {"path", "upstreamRepo", "upstreamPath", "reviewedCommit", "availableCommit", "upstreamSha256", "localSha256", "runtimeCommit", "spdx", "licensePath", "triggerHost", "triggerPath", "reviewedAt", "modifications"}
    for entry in entries:
        if missing := required - entry.keys():
            fail(f"manifest entry missing fields: {sorted(missing)}")
        path = (ROOT / entry["path"]).resolve()
        if path.parent != SCRIPT_ROOT or path.suffix != ".js" or path in listed:
            fail(f"invalid or duplicate vendor path: {entry['path']}")
        listed.add(path)
        if (
            entry["path"] != SCRIPT_PATH
            or entry["triggerHost"] != TRIGGER_HOST
            or entry["triggerPath"] != TRIGGER_PATH
            or entry["runtimeCommit"] != SCRIPT_RUNTIME_COMMIT
        ):
            fail("manifest script path, trigger, or runtime commit does not match the configuration declaration")
        if (
            not COMMIT_RE.fullmatch(entry["reviewedCommit"])
            or not COMMIT_RE.fullmatch(entry["availableCommit"])
            or not COMMIT_RE.fullmatch(entry["runtimeCommit"])
        ):
            fail(f"invalid commit metadata: {entry['path']}")
        for field in ("upstreamSha256", "localSha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", entry[field]):
                fail(f"invalid {field}: {entry['path']}")
        license_path = (ROOT / entry["licensePath"]).resolve()
        if not license_path.is_file() or ROOT.resolve() not in license_path.parents:
            fail(f"missing license file: {entry['licensePath']}")
        raw = path.read_bytes()
        if len(raw) > 20 * 1024 or b"\x00" in raw or not raw.endswith(b"\n"):
            fail(f"invalid size/NUL/final newline: {entry['path']}")
        source = raw.decode("utf-8", errors="strict")
        if hashlib.sha256(raw).hexdigest() != entry["localSha256"]:
            fail(f"local hash mismatch: {entry['path']}")
        for name, pattern in FORBIDDEN_SCRIPT_PATTERNS.items():
            if match := re.search(pattern, source, re.IGNORECASE):
                fail(f"{entry['path']}:{source.count(chr(10), 0, match.start()) + 1}: forbidden {name}")
        if source.count("$done(") != 1:
            fail(f"{entry['path']} must call $done exactly once")
        checked = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
        if checked.returncode:
            fail(f"node syntax check failed: {checked.stderr.strip()}")
    if actual != listed:
        fail("manifest JS inventory mismatch")

    derived = manifest.get("derivedSources")
    if not isinstance(derived, list) or not derived:
        fail("vendor manifest must inventory derived static sources")
    required = {"path", "upstreamRepo", "upstreamPath", "reviewedCommit", "availableCommit", "upstreamSha256", "localSha256", "spdx", "reviewedAt", "modifications"}
    for entry in derived:
        if missing := required - entry.keys():
            fail(f"derived source entry missing fields: {sorted(missing)}")
        path = (ROOT / entry["path"]).resolve()
        if not path.is_file() or ROOT.resolve() not in path.parents:
            fail(f"invalid derived source path: {entry['path']}")
        if not COMMIT_RE.fullmatch(entry["reviewedCommit"]) or not COMMIT_RE.fullmatch(entry["availableCommit"]):
            fail(f"invalid derived commit metadata: {entry['path']}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["localSha256"]:
            fail(f"derived source local hash mismatch: {entry['path']}")


def validate_workflows() -> None:
    workflow_dir = ROOT / ".github" / "workflows"
    workflows = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
    expected = {"ci.yml", "upstream-check.yml", "sync-rules.yml"}
    if {path.name for path in workflows} != expected:
        fail("workflow inventory must contain only ci.yml, upstream-check.yml, and sync-rules.yml")
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        if "\t" in text or not text.endswith("\n") or "pull_request_target" in text:
            fail(f"unsafe workflow formatting/trigger: {path.name}")
        uses = re.findall(r"(?m)^\s*-?\s*uses:\s*(\S+)", text)
        if uses != [CHECKOUT]:
            fail(f"only pinned checkout is allowed in {path.name}: {uses}")
        for required in ("name:", "on:", "permissions:", "jobs:", "runs-on: ubuntu-latest"):
            if required not in text:
                fail(f"workflow structure missing {required}: {path.name}")
    sync = (workflow_dir / "sync-rules.yml").read_text(encoding="utf-8")
    if "git add rules/generated" not in sync or re.search(r"git add .*vendor|git add .*tools", sync):
        fail("route updater may commit only generated route data")


def main() -> int:
    try:
        validate_generated()
        validate_config(DIST.read_text(encoding="utf-8"))
        validate_vendor()
        validate_workflows()
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        print(f"validation failed: {error}", file=sys.stderr)
        return 1
    print("validation passed: config, generated route data, vendor scripts, and workflows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
