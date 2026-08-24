# Third-party notices

## app2smile/rules

- Repository: https://github.com/app2smile/rules
- License: MIT (`vendor/licenses/app2smile-MIT.txt`)
- Reviewed source: `js/bilibili-json.js`
- Reviewed commit: `5380447220ea3df4abee8b77dd118de9165631fa`
- Upstream SHA-256: `748ad16a92532bde2c439a8b9975f465381d20e24328cf2a58ff3a2a27328d84`
- Local file: `vendor/scripts/bilibili-ads.js`
- Local SHA-256: `ce44680e2e347504942efe22ba0efdfe3c27458a6d618ae8fe4c73b92ea6fca9`
- Immutable runtime commit: `9b925153cffcc243d9e8625f8e8ae43e03d9c410`
- Review date: 2026-08-17
- Changes: removed notifications, tab and general UI cleanup, request-method checks, and unrelated branches. Retained only endpoint-bounded Bilibili splash and feed advertising removal with fail-open handling.

## fmz200/wool_scripts

- Repository: https://github.com/fmz200/wool_scripts
- License: GPL-3.0
- Reviewed source: `QuantumultX/rewrite/rewrite.snippet`
- Reviewed commit: `9069a18f8803a5f6904c4ed234870973605e265a`
- Upstream SHA-256: `be950bd64086028e7fc092b40ff1b32b809443749ede70406cf0aeedf33ee516`
- Local derived file: `rewrites/apps.list`
- Local SHA-256: `ff35cc7b0de0b5919ed7793780fb0d82d57060f7e56afea986272d240e22a267`
- Review date: 2026-08-24
- Changes: selected app-scoped static ad, promotion, sponsor, and watermark endpoints and converted them to Shadowrocket syntax. Removed unsupported Weibo entries and iQIYI/Youku rules that rejected full content or playback responses. Added a ByteDance ad-network section derived from the upstream Fanqie Novel, 汽水音乐, and 书旗小说 blocks: visible `get_ads` requests on the three reviewed SDK domain families receive an empty JSON object before those domains use `REJECT-200`, so `settings`, `stats`, bidding, unknown paths, and HTTP/3 are intercepted instead of `DIRECT`. Ad material, delivery packages, reporting, and the `dsp.toutiao.com` ad endpoint are rejected. No upstream scripts or unlock rules were copied.

## Loyalsoldier/clash-rules

- Repository: https://github.com/Loyalsoldier/clash-rules
- License: GPL-3.0
- Sources: release payloads `reject.txt`, `direct.txt`, `proxy.txt`, and `private.txt`
- Local derived files: `rules/generated/reject.list`, `direct.list`, `proxy.list`, and `private.list`
- Provenance: the exact release commit, source URL, source SHA-256, output SHA-256, and record count are recorded in `rules/generated/metadata.json`; each list also records its source and commit.
- Changes: strict schema conversion only. Clash suffix entries such as `+.example.com` become Shadowrocket suffix entries `.example.com`; plain domains remain exact.

The generated files retain reviewable data changes in this repository. Their automatic refresh is an explicit trust relationship with the mutable Loyalsoldier release branch.

## SagerNet/sing-geosite

- Repository: https://github.com/SagerNet/sing-geosite
- License: GPL-3.0
- Sources: `rule-set` branch files `geosite-github.srs`, `geosite-apple.srs`, `geosite-icloud.srs`, and `geosite-microsoft.srs`
- Local derived files: `rules/generated/github.list`, `apple.list`, `icloud.list`, and `microsoft.list`
- Provenance: the exact `rule-set` commit, input/output SHA-256, record count, and converter identity are recorded in `rules/generated/metadata.json`; each list also records its source, commit, and tool version.
- Changes: official sing-box decompilation followed by strict conversion of `domain`, `domain_suffix`, and `domain_keyword` fields to typed Shadowrocket `RULE-SET` records.

The sing-geosite generator source explicitly downloads the latest `v2fly/domain-list-community` release and converts its `dlc.dat`; that upstream data project is MIT-licensed. This lineage is stated here because the selected SRS data is produced through that path.

## SagerNet/sing-box

- Repository: https://github.com/SagerNet/sing-box
- Version used as a build tool: 1.13.19
- Use: official `rule-set decompile` converts pinned sing-geosite SRS bytes to documented source JSON during regeneration; sing-box is not distributed in this repository.
- Integrity: the official Windows amd64 ZIP and Linux amd64 tarball names and SHA-256 values are pinned in `tools/sync_rules.py` and `rules/generated/metadata.json`. Downloads are restricted to the official GitHub release URL and cached under ignored `.cache/`.
- License: the upstream license grants GPL version 3 or later and includes an additional restriction on derivative use of the application name or implied association.

## Loyalsoldier/geoip release data

The configuration references these generated release data files without redistributing them:

- https://raw.githubusercontent.com/Loyalsoldier/geoip/release/surge/private.txt
- https://raw.githubusercontent.com/Loyalsoldier/geoip/release/surge/cn.txt

The generated GeoIP data is licensed under CC-BY-SA-4.0 and incorporates upstream data, including GeoLite2 data created by MaxMind and available from https://www.maxmind.com/. The upstream project documents additional selectable providers such as DB-IP and IPInfo; consult https://github.com/Loyalsoldier/geoip for the current generation inputs and attribution requirements.

The Loyalsoldier/geoip source code is separately offered under GPL-3.0 (`LICENSE-GPL` upstream). That code license must not be confused with the CC-BY-SA-4.0 license covering the generated route data referenced here.
