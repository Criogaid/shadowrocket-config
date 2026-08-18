from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_upstream
import validate


class ConfigRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = (ROOT / "dist" / "shadowrocket.conf").read_text(encoding="utf-8")

    def assert_rejected(self, text: str) -> None:
        with self.assertRaises(ValueError):
            validate.validate_config(text)

    def test_current_config_and_generated_inventory(self) -> None:
        validate.validate_generated()
        validate.validate_config(self.text)

    def test_encrypted_dns_protocols_and_hosts_are_exact(self) -> None:
        self.assertNotIn("#proxy=PROXY", self.text)
        self.assertIn(f"direct-dns-server = {validate.DIRECT_DNS}", self.text)
        self.assert_rejected(self.text.replace("#proxy,", "#proxy=PROXY,", 1))
        self.assert_rejected(self.text.replace("quic://dns.alidns.com:853", "tls://dns.alidns.com:853"))
        self.assertEqual(validate.data_lines(validate.sections(self.text)["Host"]), list(validate.DNS_HOSTS))
        self.assert_rejected(self.text.replace("dns.quad9.net = 9.9.9.9", "dns.quad9.net = 149.112.112.112"))
        self.assert_rejected(self.text.replace("dns.alidns.com = 223.5.5.5", "dns.alidns.com = 223.6.6.6"))
        self.assert_rejected(self.text.replace("doh.pub = 120.53.53.53", "doh.pub = 1.12.12.12"))
        self.assert_rejected(self.text.replace("dot.pub = 120.53.53.53", "dot.pub = 1.12.12.12"))
        self.assert_rejected(self.text.replace("use-local-host-item-for-proxy = true", "use-local-host-item-for-proxy = false"))

    def test_authoritative_service_rule_sets_have_exact_order_and_types(self) -> None:
        ordered = [validate.GENERATED_RULES[name] for name in ("github", "apple", "icloud", "microsoft", "private", "proxy", "direct")]
        positions = [self.text.index(rule) for rule in ordered]
        self.assertEqual(positions, sorted(positions))
        for name in ("github", "apple", "icloud", "microsoft"):
            self.assertTrue(validate.GENERATED_RULES[name].startswith("RULE-SET,"))
        self.assertNotIn("v2ray-rules-dat", self.text)
        self.assert_rejected(self.text.replace(validate.GENERATED_RULES["apple"], "DOMAIN-SET,https://example/apple.list,DIRECT"))

    def test_handwritten_service_fallbacks_are_absent_and_rejected(self) -> None:
        for domain in validate.HANDWRITTEN_SERVICE_SUFFIXES:
            self.assertNotIn(f"DOMAIN-SUFFIX,{domain},", self.text)
        marker = validate.GENERATED_RULES["microsoft"]
        self.assert_rejected(self.text.replace(marker, marker + "\nDOMAIN-SUFFIX,office.net,DIRECT"))

    def test_unsafe_full_response_rules_are_absent(self) -> None:
        apps = (ROOT / "rewrites" / "apps.list").read_text(encoding="utf-8")
        for unsafe in ("cupid.iqiyi", "youku.play", "bootpreload", "bootrealtime"):
            self.assertNotIn(unsafe, apps)

    def test_exact_mitm_inventory_rejects_additions_duplicates_and_broadening(self) -> None:
        host_line = f"hostname = {','.join(validate.MITM_HOSTS)}"
        for replacement in (
            host_line + ",extra.example",
            host_line + ",app.bilibili.com",
            host_line.replace("interface.music.163.com,interface3.music.163.com,ipv4.music.163.com", "*.music.163.com"),
            "hostname = *",
        ):
            with self.subTest(replacement=replacement[-40:]):
                self.assert_rejected(self.text.replace(host_line, replacement))
        self.assert_rejected(self.text.replace("h2 = true", "h2 = false"))

    def test_script_declaration_is_exactly_bound(self) -> None:
        self.assertEqual(validate.data_lines(validate.sections(self.text)["Script"]), [validate.SCRIPT_LINE])
        self.assert_rejected(self.text.replace("feed/index)(?:\\?|$)", "feed/index-old)"))


class WorkflowRegressionTests(unittest.TestCase):
    def test_yaml_extension_is_inspected_and_rejected_as_extra(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / ".github" / "workflows"
            shutil.copytree(ROOT / ".github" / "workflows", target)
            (target / "extra.yaml").write_text("name: Extra\n", encoding="utf-8")
            with mock.patch.object(validate, "ROOT", root), self.assertRaises(ValueError):
                validate.validate_workflows()

    def test_current_workflows_are_exact(self) -> None:
        validate.validate_workflows()


class GitHubAuthenticationTests(unittest.TestCase):
    def test_check_upstream_uses_gh_token(self) -> None:
        captured = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.close()

        def open_request(request, timeout):
            captured.append((request, timeout))
            return Response(json.dumps([{"sha": "a" * 40}]).encode())

        with mock.patch.dict(os.environ, {"GH_TOKEN": "secret"}), mock.patch("urllib.request.urlopen", side_effect=open_request):
            self.assertEqual(check_upstream.latest_commit("owner/repo", "path"), "a" * 40)
        self.assertEqual(captured[0][0].get_header("Authorization"), "Bearer secret")


if __name__ == "__main__":
    unittest.main()
