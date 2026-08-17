from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import sync_rules


def source(rules: object, version: object = 1) -> bytes:
    return json.dumps({"version": version, "rules": rules}).encode()


class PayloadConversionTests(unittest.TestCase):
    def test_suffix_exact_and_stable_deduplication(self) -> None:
        raw = b"payload:\n  - '+.example.com'\n  - 'exact.example.com'\n  - '+.example.com'\n"
        self.assertEqual(sync_rules.convert_payload(raw), [".example.com", "exact.example.com"])

    def test_render_includes_traceable_source_commit_and_tool(self) -> None:
        commit = "a" * 40
        rendered = sync_rules.render_list("https://example/geosite.srs", commit, ["DOMAIN,example.com"], "1.13.19")
        self.assertIn(b"# Source: https://example/geosite.srs\n", rendered)
        self.assertIn(f"# Commit: {commit}\n".encode(), rendered)
        self.assertIn(b"# Tool: SagerNet/sing-box 1.13.19\n", rendered)

    def test_rejects_every_unsupported_fixture(self) -> None:
        fixtures = {
            "bom": b"\xef\xbb\xbfpayload:\n  - 'example.com'\n",
            "crlf": b"payload:\r\n  - 'example.com'\r\n",
            "missing final newline": b"payload:\n  - 'example.com'",
            "broad yaml": b"payload:\n- 'example.com'\n",
            "double quoted": b'payload:\n  - "example.com"\n',
            "comment": b"payload:\n  - 'example.com' # no\n",
            "blank line": b"payload:\n\n  - 'example.com'\n",
            "regexp": b"payload:\n  - 'regexp:example'\n",
            "full": b"payload:\n  - 'full:example.com'\n",
            "comma injection": b"payload:\n  - 'example.com,PROXY'\n",
            "unicode": "payload:\n  - '例子.中国'\n".encode(),
            "empty": b"payload:\n",
        }
        for name, raw in fixtures.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                sync_rules.convert_payload(raw)

    def test_check_fails_for_unexpected_generated_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            (output / "extra.list").write_text("unexpected\n", encoding="ascii")
            with mock.patch.object(sync_rules, "OUTPUT_DIR", output), redirect_stderr(io.StringIO()):
                self.assertFalse(sync_rules.write_or_check({"direct.list": b"x\n"}, b"{}\n", True))

    def test_pinned_commits_and_regeneration_reject_mutated_output(self) -> None:
        clash_commit = "a" * 40
        geosite_commit = "b" * 40
        metadata = {
            "sources": [
                {"id": "clash-rules", "commit": clash_commit},
                {"id": "sing-geosite", "commit": geosite_commit},
            ]
        }
        regenerated = json.dumps(metadata, indent=2).encode() + b"\n"
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            (output / "metadata.json").write_bytes(regenerated)
            (output / "direct.list").write_bytes(b"tampered\n")
            with mock.patch.object(sync_rules, "OUTPUT_DIR", output), redirect_stderr(io.StringIO()):
                self.assertEqual(sync_rules.pinned_commits(), (clash_commit, geosite_commit))
                self.assertFalse(sync_rules.write_or_check({"direct.list": b"reviewed\n"}, regenerated, True))


class GeositeConversionTests(unittest.TestCase):
    def test_exact_suffix_keyword_scalar_list_and_stable_deduplication(self) -> None:
        raw = source([
            {"domain": "exact.example", "domain_suffix": [".suffix.example", "suffix.example"], "domain_keyword": "keyword"},
            {"domain": ["second.example", "exact.example"], "domain_keyword": ["cdn-", "keyword"]},
        ])
        self.assertEqual(sync_rules.convert_geosite_json(raw), [
            "DOMAIN,exact.example",
            "DOMAIN-SUFFIX,suffix.example",
            "DOMAIN-KEYWORD,keyword",
            "DOMAIN,second.example",
            "DOMAIN-KEYWORD,cdn-",
        ])

    def test_rejects_non_domain_and_unknown_rule_fields(self) -> None:
        fields = {
            "domain_regex": [".*"],
            "ip_cidr": ["1.2.3.0/24"],
            "port": [443],
            "invert": True,
            "type": "logical",
            "rules": [],
            "unknown": "value",
        }
        for field, value in fields.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                sync_rules.convert_geosite_json(source([{field: value}]))

    def test_rejects_malformed_roots_versions_and_values(self) -> None:
        fixtures = {
            "array root": b"[]",
            "missing rules": b'{"version":1}',
            "extra root": b'{"version":1,"rules":[],"extra":true}',
            "wrong version": source([{"domain": "example.com"}], 2),
            "boolean version": source([{"domain": "example.com"}], True),
            "empty rules": source([]),
            "non-object rule": source(["example.com"]),
            "empty rule": source([{}]),
            "empty list": source([{"domain": []}]),
            "non-string list": source([{"domain": ["example.com", 1]}]),
            "bad domain": source([{"domain": "example.com,PROXY"}]),
            "bad keyword": source([{"domain_keyword": "bad,keyword"}]),
        }
        for name, raw in fixtures.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                sync_rules.convert_geosite_json(raw)


class ConverterToolTests(unittest.TestCase):
    def test_selects_only_pinned_supported_assets(self) -> None:
        self.assertEqual(sync_rules.select_tool_asset("Windows", "AMD64")["sha256"], "e011a4def2f5e2b143ed54adb2b1a20a6be407806ab4442f3667f1dd817a2c8d")
        self.assertEqual(sync_rules.select_tool_asset("Linux", "x86_64")["sha256"], "ef88a9e577d474210867bd708933d042e9b70106529df2656182c9db90106aa1")
        for system, machine in (("Darwin", "x86_64"), ("Linux", "aarch64")):
            with self.subTest(system=system, machine=machine), self.assertRaises(ValueError):
                sync_rules.select_tool_asset(system, machine)

    def test_digest_rejection(self) -> None:
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            sync_rules.verify_digest(b"tampered", "0" * 64, "asset")


if __name__ == "__main__":
    unittest.main()
