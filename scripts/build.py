#!/usr/bin/env python3
"""Build comprehensive Anywhere .arrs rule sets.

Routing model:

  * default route -> proxy
  * CN-Domains-*.arrs, CN-IP.arrs -> DIRECT
  * Apple.arrs, Tesla.arrs, Foreign-Direct.arrs -> DIRECT
  * LAN.arrs -> DIRECT

Sources: Loyalsoldier, blackmatrix7, Karing, XTLS Xray-rules-dat and
ACL4SSR.  The generated sets are intentionally explicit DIRECT exceptions;
foreign traffic that is not listed falls through to the default proxy.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

DEFAULT_REPO = "lhxyzCJ/anywhere-proxy-rule"
USER_AGENT = "anywhere-proxy-rule/2.0 (+https://github.com/lhxyzCJ/anywhere-proxy-rule)"

# Current Anywhere builds allow 200,000 rules per custom set (the
# documentation still mentions 100,000).  Individual CN sets are still split
# conservatively so they also work on older builds.
MAX_RULES_PER_SET = 200_000
DEFAULT_SPLIT_LIMIT = 90_000
CHINA_TZ = timezone(timedelta(hours=8))

LOYAL = "Loyalsoldier/clash-rules"
BM7 = "blackmatrix7/ios_rule_script"
KARING = "KaringX/karing-ruleset"
XRAY_RELEASE = "https://github.com/XTLS/Xray-rules-dat/releases/latest/download/{asset}"

# Domains that are too broad to live in a DIRECT set.  Exact matches only:
# specific subdomains such as apple.com.akadns.net remain allowed.
BROAD_DIRECT_SUFFIXES = {
    "akadns.net",
    "akamaized.net",
    "akamai.net",
    "amazonaws.com",
    "azureedge.net",
    "cloudfront.net",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
}

GENERIC_TLDS = {
    "ai",
    "app",
    "biz",
    "blog",
    "cloud",
    "club",
    "co",
    "com",
    "dev",
    "info",
    "io",
    "live",
    "me",
    "net",
    "news",
    "online",
    "org",
    "shop",
    "site",
    "top",
    "xyz",
}

# Full vendor categories are useful for driver/software downloads, but a few
# entries in those categories must stay on the proxy.
FOREIGN_DIRECT_DENYLIST = {
    "github.ai",
    "github.blog",
    "github.career",
    "github.com",
    "github.community",
    "github.dev",
    "github.io",
    "githubapp.com",
    "hf.co",
    "hf.space",
    "huggingface.co",
}

# Privacy / DNS-leak test sites must never be DIRECT, otherwise the test page
# itself is resolved by the local ISP resolver and reports a Chinese DNS IP.
# blackmatrix7's ChinaMax_Domain currently contains browserleaks.com.
NEVER_DIRECT_DOMAINS = {
    "browserleaks.com",
    "browserleaks.io",
    "browserleaks.net",
    "browserleaks.org",
    "dnsleaktest.com",
    "ipleak.net",
    "whoer.net",
    "dnscheck.tools",
    "dnschecker.org",
    "whatleaks.com",
    "test-ipv6.com",
    "ipv6-test.com",
    "whatismyipaddress.com",
}

# Steam download CDNs are the only Steam-related domains that should be
# direct.  The store, community, login and client-update infrastructure stays
# on the proxy.  Domain entries are stored as suffixes because Anywhere has no
# exact-domain rule type; the listed subdomains are still scoped correctly.
STEAM_DOWNLOAD_DOMAINS = {
    "steamcontent.com",
    "steamcontent.tnkjmec.com",
    "steampipe.akamaized.net",
    "steamserver.net",
    "cm.steampowered.com",
    "steamcdn-a.akamaihd.net",
    "client-update.queniuqe.com",
    "dl.steam.clngaa.com",
    "st.dl.bscstorage.net",
    "st.dl.eccdnx.com",
    "st.dl.pinyuncloud.com",
    "dl.steam.ksyna.com",
    "lv.queniujq.cn",
    "xz.pphimalayanrt.com",
    "steampowered.com.8686c.com",
    "content.steamchina.com",
}

Rule = tuple[int, str]


def mirrors(repo: str, ref: str, path: str) -> tuple[str, ...]:
    return (
        f"https://cdn.jsdelivr.net/gh/{repo}@{ref}/{path}",
        f"https://fastly.jsdelivr.net/gh/{repo}@{ref}/{path}",
        f"https://raw.githubusercontent.com/{repo}/{ref}/{path}",
    )


@dataclass(frozen=True)
class Download:
    key: str
    urls: tuple[str, ...]
    min_bytes: int
    label: str


@dataclass
class Parsed:
    rules: list[Rule]
    invalid: int = 0
    skipped: int = 0


DOWNLOADS: tuple[Download, ...] = (
    # Loyalsoldier / Clash
    Download("loyalsoldier-direct", mirrors(LOYAL, "release", "direct.txt"), 1_500_000, "Loyalsoldier direct"),
    Download("loyalsoldier-cncidr", mirrors(LOYAL, "release", "cncidr.txt"), 150_000, "Loyalsoldier cncidr"),
    Download("loyalsoldier-apple", mirrors(LOYAL, "release", "apple.txt"), 4_000, "Loyalsoldier apple"),
    Download("loyalsoldier-icloud", mirrors(LOYAL, "release", "icloud.txt"), 800, "Loyalsoldier icloud"),
    Download("loyalsoldier-lancidr", mirrors(LOYAL, "release", "lancidr.txt"), 300, "Loyalsoldier lancidr"),
    Download("loyalsoldier-private", mirrors(LOYAL, "release", "private.txt"), 2_000, "Loyalsoldier private"),
    # blackmatrix7 / Clash
    Download("bm7-chinamax-domain", mirrors(BM7, "master", "rule/Clash/ChinaMax/ChinaMax_Domain.yaml"), 1_500_000, "blackmatrix7 ChinaMax domain"),
    Download("bm7-chinamax-ip", mirrors(BM7, "master", "rule/Clash/ChinaMax/ChinaMax_IP.yaml"), 150_000, "blackmatrix7 ChinaMax IP"),
    Download("bm7-apple-domain", mirrors(BM7, "master", "rule/Clash/Apple/Apple_Domain.yaml"), 25_000, "blackmatrix7 Apple domain"),
    Download("bm7-apple", mirrors(BM7, "master", "rule/Clash/Apple/Apple.yaml"), 500, "blackmatrix7 Apple rules"),
    Download("bm7-tesla", mirrors(BM7, "master", "rule/Clash/Tesla/Tesla.yaml"), 300, "blackmatrix7 Tesla"),
    # Karing / sing-box geo data
    Download("karing-cn", mirrors(KARING, "sing", "geo/geosite/cn.json"), 1_500_000, "Karing geosite cn"),
    Download("karing-apple", mirrors(KARING, "sing", "geo/geosite/apple.json"), 30_000, "Karing geosite apple"),
    Download("karing-tesla", mirrors(KARING, "sing", "geo/geosite/tesla.json"), 200, "Karing geosite tesla"),
    Download("karing-microsoft-cn", mirrors(KARING, "sing", "geo/geosite/microsoft@cn.json"), 3_000, "Karing geosite microsoft@cn"),
    Download("karing-nvidia-cn", mirrors(KARING, "sing", "geo/geosite/nvidia@cn.json"), 100, "Karing geosite nvidia@cn"),
    Download("karing-samsung-cn", mirrors(KARING, "sing", "geo/geosite/samsung@cn.json"), 50, "Karing geosite samsung@cn"),
    Download("karing-nintendo-cn", mirrors(KARING, "sing", "geo/geosite/nintendo@cn.json"), 100, "Karing geosite nintendo@cn"),
    Download("karing-steam-cn", mirrors(KARING, "sing", "geo/geosite/steam@cn.json"), 100, "Karing geosite steam@cn"),
    Download("karing-google-cn", mirrors(KARING, "sing", "geo/geosite/google@cn.json"), 1_000, "Karing geosite google@cn"),
    Download("karing-cn-ip", mirrors(KARING, "sing", "geo/geoip/cn.json"), 150_000, "Karing geoip cn"),
    Download("karing-private-ip", mirrors(KARING, "sing", "geo/geoip/private.json"), 300, "Karing geoip private"),
    # Karing's bundled ACL4SSR rule fragments
    Download("acl4ssr-china-domain", mirrors(KARING, "sing", "ACL4SSR/ChinaDomain.json"), 5_000, "ACL4SSR ChinaDomain"),
    Download("acl4ssr-china-ip", mirrors(KARING, "sing", "ACL4SSR/ChinaIp.json"), 80_000, "ACL4SSR ChinaIp"),
    Download("acl4ssr-apple", mirrors(KARING, "sing", "ACL4SSR/Apple.json"), 300, "ACL4SSR Apple"),
    # XTLS Xray-maintained geo rules
    Download("xray-geosite", (XRAY_RELEASE.format(asset="geosite.dat"),), 5_000_000, "XTLS geosite.dat"),
    Download("xray-geoip", (XRAY_RELEASE.format(asset="geoip-lite.dat"),), 2_000_000, "XTLS geoip-lite.dat"),
)


def parse_payload(text: str) -> list[str]:
    """Parse a Clash rule-provider style ``payload:`` text file."""
    values: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        elif line.endswith(":"):
            continue
        if len(line) >= 2 and line[0] == line[-1] and line[0] in "'\"":
            line = line[1:-1]
        if line:
            values.append(line)
    return values


def normalize_domain(value: str) -> str | None:
    value = value.strip().strip("'\"").strip()
    if value.startswith("+.") or value.startswith("*."):
        value = value[2:]
    value = value.lstrip(".").rstrip(".").lower()
    if not value or len(value) > 253:
        return None
    # Reject stray single characters such as the malformed Karing @cn lists.
    if "." not in value and len(value) == 1:
        return None

    if any(ord(char) > 127 for char in value):
        try:
            value = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None

    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return None
    return value


def valid_keyword(value: str) -> bool:
    value = value.strip().lower()
    return (
        len(value) >= 2
        and value not in {".", ".."}
        and bool(re.fullmatch(r"[a-z0-9._-]+", value))
    )


def network_rule(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> Rule:
    """Convert a network, folding IPv4-mapped IPv6 ranges back to IPv4."""
    if isinstance(network, ipaddress.IPv6Network):
        mapped = network.network_address.ipv4_mapped
        if mapped is not None and network.prefixlen > 96:
            prefix = network.prefixlen - 96
            return 0, str(ipaddress.ip_network((mapped, prefix), strict=False))
    return (0 if network.version == 4 else 1), str(network)


def to_rule(value: str) -> Rule | None:
    """Convert one source entry to an Anywhere ``(type, value)`` rule."""
    value = value.strip().strip("'\"").strip()
    if not value:
        return None

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        pass
    else:
        return network_rule(network)

    domain = normalize_domain(value)
    if domain:
        return 2, domain
    return None


def parse_clash_value(value: str) -> Rule | None:
    value = value.strip().strip("'\"").strip()
    if not value:
        return None

    if "," in value:
        prefix, rest = value.split(",", 1)
        prefix = prefix.strip().upper()
        rest = rest.split(",", 1)[0].strip()

        if prefix in {"DOMAIN", "DOMAIN-SUFFIX"}:
            domain = normalize_domain(rest)
            return (2, domain) if domain else None
        if prefix == "DOMAIN-KEYWORD":
            keyword = rest.lower().strip()
            return (3, keyword) if valid_keyword(keyword) else None
        if prefix in {"IP-CIDR", "IP-CIDR6"}:
            return to_rule(rest)
        # PROCESS-NAME, IP-ASN, GEOIP, RULE-SET and similar are unsupported.
        return None

    return to_rule(value)


def parse_clash(text: str) -> Parsed:
    rules: list[Rule] = []
    invalid = 0
    for value in parse_payload(text):
        rule = parse_clash_value(value)
        if rule:
            rules.append(rule)
        else:
            invalid += 1
    return Parsed(rules, invalid)


def parse_karing_json(data: bytes) -> Parsed:
    document = json.loads(data.decode("utf-8"))
    rules: list[Rule] = []
    invalid = 0
    skipped = 0

    for item in document.get("rules", []):
        for key in ("domain", "domain_suffix"):
            for value in item.get(key, []):
                rule = to_rule(value)
                if rule:
                    rules.append(rule)
                else:
                    invalid += 1
        for value in item.get("domain_keyword", []):
            keyword = str(value).lower().strip()
            if valid_keyword(keyword):
                rules.append((3, keyword))
            else:
                invalid += 1
        for value in item.get("ip_cidr", []):
            rule = to_rule(value)
            if rule:
                rules.append(rule)
            else:
                invalid += 1
        skipped += len(item.get("domain_regex", []))
        skipped += len(item.get("process_name", []))
        skipped += len(item.get("package_name", []))

    return Parsed(rules, invalid, skipped)


# ---------------------------------------------------------------------------
# Minimal protobuf reader for XTLS geosite.dat / geoip.dat
# ---------------------------------------------------------------------------


def _read_varint(data: bytes, position: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if position >= len(data):
            raise ValueError("truncated varint")
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _proto_fields(data: bytes) -> Iterator[tuple[int, int, object]]:
    position = 0
    while position < len(data):
        key, position = _read_varint(data, position)
        field = key >> 3
        wire = key & 0x07
        if wire == 0:
            value, position = _read_varint(data, position)
        elif wire == 2:
            length, position = _read_varint(data, position)
            end = position + length
            if end > len(data):
                raise ValueError("truncated length-delimited field")
            value = data[position:end]
            position = end
        elif wire == 1:
            value = data[position : position + 8]
            position += 8
        elif wire == 5:
            value = data[position : position + 4]
            position += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        yield field, wire, value


def _parse_xray_attribute(data: bytes) -> tuple[str, bool]:
    key = ""
    value = False
    for field, wire, raw in _proto_fields(data):
        if field == 1 and wire == 2:
            key = raw.decode("utf-8", "replace").lower()
        elif field == 2 and wire == 0:
            value = bool(raw)
    return key, value


def _parse_xray_domain(data: bytes) -> tuple[int, str, set[str]]:
    rule_type = 0
    value = ""
    attributes: set[str] = set()
    for field, wire, raw in _proto_fields(data):
        if field == 1 and wire == 0:
            rule_type = int(raw)
        elif field == 2 and wire == 2:
            value = raw.decode("utf-8", "replace")
        elif field == 3 and wire == 2:
            key, enabled = _parse_xray_attribute(raw)
            if key and enabled:
                attributes.add(key)
    return rule_type, value, attributes


def parse_xray_geosite(data: bytes) -> dict[str, list[tuple[int, str, set[str]]]]:
    sites: dict[str, list[tuple[int, str, set[str]]]] = {}
    for field, wire, raw in _proto_fields(data):
        if field != 1 or wire != 2:
            continue
        code = ""
        domains: list[tuple[int, str, set[str]]] = []
        for inner_field, inner_wire, inner in _proto_fields(raw):
            if inner_field == 1 and inner_wire == 2:
                code = inner.decode("utf-8", "replace")
            elif inner_field == 2 and inner_wire == 2:
                domains.append(_parse_xray_domain(inner))
        if code:
            sites.setdefault(code, []).extend(domains)
    return sites


def parse_xray_geoip(data: bytes) -> dict[str, list[Rule]]:
    sites: dict[str, list[Rule]] = {}
    for field, wire, raw in _proto_fields(data):
        if field != 1 or wire != 2:
            continue
        code = ""
        cidrs: list[Rule] = []
        for inner_field, inner_wire, inner in _proto_fields(raw):
            if inner_field == 1 and inner_wire == 2:
                code = inner.decode("utf-8", "replace")
            elif inner_field == 2 and inner_wire == 2:
                address = None
                prefix = 0
                for cidr_field, cidr_wire, cidr_value in _proto_fields(inner):
                    if cidr_field == 1 and cidr_wire == 2:
                        address = cidr_value
                    elif cidr_field == 2 and cidr_wire == 0:
                        prefix = int(cidr_value)
                if address is None:
                    continue
                try:
                    network = ipaddress.ip_network(
                        (ipaddress.ip_address(address), prefix), strict=False
                    )
                except ValueError:
                    continue
                cidrs.append(network_rule(network))
        if code:
            sites.setdefault(code, []).extend(cidrs)
    return sites


def xray_site_rules(
    sites: dict[str, list[tuple[int, str, set[str]]]],
    categories: Iterable[str],
    only_cn: bool = False,
) -> Parsed:
    rules: list[Rule] = []
    invalid = 0
    skipped = 0
    for category in categories:
        for rule_type, value, attributes in sites.get(category, []):
            if rule_type == 1:
                skipped += 1
                continue
            if only_cn and "cn" not in attributes:
                skipped += 1
                continue
            rule = to_rule(value)
            if rule:
                rules.append(rule)
            else:
                invalid += 1
    return Parsed(rules, invalid, skipped)


# ---------------------------------------------------------------------------
# Download and output helpers
# ---------------------------------------------------------------------------


def fetch_one(
    spec: Download,
    cache_dir: Path | None,
    refresh: bool,
    attempts: int,
    timeout: int,
) -> tuple[bytes, str]:
    cache_path = cache_dir / spec.key if cache_dir else None
    if cache_path and cache_path.exists() and not refresh:
        data = cache_path.read_bytes()
        if len(data) >= spec.min_bytes:
            return data, f"cache:{cache_path}"

    errors: list[str] = []
    for attempt in range(1, attempts + 1):
        for url in spec.urls:
            try:
                request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    if response.status != 200:
                        raise RuntimeError(f"HTTP {response.status}")
                    data = response.read()
                if len(data) < spec.min_bytes:
                    raise RuntimeError(
                        f"only {len(data)} bytes, expected at least {spec.min_bytes}"
                    )
                if cache_path:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_bytes(data)
                return data, url
            except Exception as exc:  # noqa: BLE001 - mirror fallback is intentional
                errors.append(f"{url}: {type(exc).__name__}: {exc}")
        if attempt < attempts:
            time.sleep(attempt * 2)

    raise RuntimeError("; ".join(errors[-6:]))


def download_all(
    specs: Iterable[Download],
    cache_dir: Path | None,
    refresh: bool,
    attempts: int,
    timeout: int,
) -> dict[str, tuple[bytes, str]]:
    specs = tuple(specs)
    results: dict[str, tuple[bytes, str]] = {}
    errors: list[str] = []

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(fetch_one, spec, cache_dir, refresh, attempts, timeout): spec
            for spec in specs
        }
        for future in as_completed(futures):
            spec = futures[future]
            try:
                results[spec.key] = future.result()
                print(f"fetched {spec.label}: {len(results[spec.key][0]):,} bytes", flush=True)
            except Exception as exc:  # noqa: BLE001 - aggregated below
                errors.append(f"{spec.key}: {exc}")
                print(f"  ! failed {spec.label}: {exc}", file=sys.stderr, flush=True)

    if errors:
        raise RuntimeError("failed to download sources:\n" + "\n".join(errors))
    return results


def dedupe_sorted(rules: Iterable[Rule]) -> list[Rule]:
    return sorted(set(rules), key=lambda rule: (rule[0], rule[1]))


def denied_direct_value(value: str, denylist: set[str]) -> bool:
    return any(value == blocked or value.endswith("." + blocked) for blocked in denylist)


def is_steam_download(value: str) -> bool:
    return any(
        value == allowed or value.endswith("." + allowed)
        for allowed in STEAM_DOWNLOAD_DOMAINS
    )


def is_steam_domain(value: str) -> bool:
    return "steam" in value


def safe_direct(rules: Iterable[Rule]) -> list[Rule]:
    result: list[Rule] = []
    for rule_type, value in rules:
        if rule_type in (2, 3) and value in BROAD_DIRECT_SUFFIXES:
            continue
        if rule_type in (2, 3) and value in GENERIC_TLDS:
            continue
        if rule_type in (2, 3) and denied_direct_value(value, NEVER_DIRECT_DOMAINS):
            continue
        if rule_type in (2, 3) and is_steam_domain(value) and not is_steam_download(value):
            continue
        result.append((rule_type, value))
    return result


def safe_cn_domains(rules: Iterable[Rule]) -> list[Rule]:
    """Prevent a malformed upstream entry such as ``com`` from matching all."""
    result: list[Rule] = []
    for rule_type, value in rules:
        if rule_type in (2, 3) and value in GENERIC_TLDS and value != "cn":
            continue
        if rule_type in (2, 3) and denied_direct_value(value, NEVER_DIRECT_DOMAINS):
            continue
        if rule_type in (2, 3) and is_steam_domain(value) and not is_steam_download(value):
            continue
        result.append((rule_type, value))
    return result


def safe_foreign_direct(rules: Iterable[Rule]) -> list[Rule]:
    result: list[Rule] = []
    for rule_type, value in safe_direct(rules):
        if rule_type in (2, 3) and denied_direct_value(value, FOREIGN_DIRECT_DENYLIST):
            continue
        result.append((rule_type, value))
    return result


def split_even(rules: list[Rule], limit: int, min_parts: int = 2) -> list[list[Rule]]:
    """Split into balanced, stable parts, each no larger than ``limit``."""
    if not rules:
        raise RuntimeError("cannot split an empty rule set")
    if limit < 1 or limit > MAX_RULES_PER_SET:
        raise ValueError(f"split limit must be between 1 and {MAX_RULES_PER_SET}")

    part_count = max(min_parts, math.ceil(len(rules) / limit))
    part_size = math.ceil(len(rules) / part_count)
    return [rules[index : index + part_size] for index in range(0, len(rules), part_size)]


def write_arrs(
    path: Path,
    name: str,
    rules: list[Rule],
    source_note: str,
    generated_at: str,
) -> dict[str, object]:
    lines = [
        f"name = {name}",
        "routing = 1",
        f"# Generated at {generated_at}",
        f"# Source: {source_note}",
        "# Rule types: 0 IPv4 CIDR, 1 IPv6 CIDR, 2 domain suffix, 3 domain keyword",
        f"# Rules: {len(rules)}",
        "",
    ]
    lines.extend(f"{rule_type}, {value}" for rule_type, value in rules)
    lines.append("")
    data = "\n".join(lines).encode("utf-8")
    path.write_bytes(data)

    return {
        "file": path.name,
        "name": name,
        "rules": len(rules),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def validate_arrs(path: Path, expected_rules: int) -> None:
    """Re-parse an output file roughly the way Anywhere does."""
    name = ""
    routing = ""
    count = 0
    seen: set[Rule] = set()

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip().lower()
            if key == "name":
                name = value.strip()
                continue
            if key == "routing":
                routing = value.strip()
                continue
        if "," not in line:
            continue
        prefix, value = line.split(",", 1)
        prefix = prefix.strip()
        value = value.strip()
        if prefix not in {"0", "1", "2", "3"} or not value:
            raise RuntimeError(f"{path}: invalid rule line: {line!r}")
        if len(value.encode("utf-8")) > 65_535:
            raise RuntimeError(f"{path}: rule value is too long")
        count += 1
        seen.add((int(prefix), value))

    if not name:
        raise RuntimeError(f"{path}: missing name header")
    if routing != "1":
        raise RuntimeError(f"{path}: routing header must be 1 (DIRECT)")
    if count != expected_rules:
        raise RuntimeError(f"{path}: wrote {expected_rules} rules but parsed {count}")
    if count > MAX_RULES_PER_SET:
        raise RuntimeError(f"{path}: {count} rules exceeds the {MAX_RULES_PER_SET} limit")
    if len(seen) != count:
        raise RuntimeError(f"{path}: duplicate rules found")


def require(label: str, rules: list[Rule], minimum: int) -> None:
    if len(rules) < minimum:
        raise RuntimeError(f"{label}: only {len(rules)} rules, expected at least {minimum}")


def build(args: argparse.Namespace) -> dict[str, object]:
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    release_date = now_utc.astimezone(CHINA_TZ).strftime("%Y.%m.%d")
    generated_at = now_utc.isoformat().replace("+00:00", "Z")
    release_tag = "rules-" + release_date

    cache_dir = Path(args.cache_dir) if args.cache_dir else None
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)

    downloaded = download_all(
        DOWNLOADS,
        cache_dir,
        refresh=args.refresh,
        attempts=args.attempts,
        timeout=args.timeout,
    )

    def text(key: str) -> str:
        return downloaded[key][0].decode("utf-8")

    parsed: dict[str, Parsed] = {}
    for key in (
        "loyalsoldier-direct",
        "loyalsoldier-cncidr",
        "loyalsoldier-apple",
        "loyalsoldier-icloud",
        "loyalsoldier-lancidr",
        "loyalsoldier-private",
        "bm7-chinamax-domain",
        "bm7-chinamax-ip",
        "bm7-apple-domain",
        "bm7-apple",
        "bm7-tesla",
    ):
        parsed[key] = parse_clash(text(key))

    for key in (
        "karing-cn",
        "karing-apple",
        "karing-tesla",
        "karing-microsoft-cn",
        "karing-nvidia-cn",
        "karing-samsung-cn",
        "karing-nintendo-cn",
        "karing-steam-cn",
        "karing-google-cn",
        "karing-cn-ip",
        "karing-private-ip",
        "acl4ssr-china-domain",
        "acl4ssr-china-ip",
        "acl4ssr-apple",
    ):
        parsed[key] = parse_karing_json(downloaded[key][0])

    geosite = parse_xray_geosite(downloaded["xray-geosite"][0])
    geoip = parse_xray_geoip(downloaded["xray-geoip"][0])
    parsed["xray-cn"] = xray_site_rules(geosite, ("CN", "GEOLOCATION-CN", "TLD-CN"))
    parsed["xray-apple"] = xray_site_rules(geosite, ("APPLE",))
    parsed["xray-tesla"] = xray_site_rules(geosite, ("TESLA",))
    parsed["xray-foreign"] = xray_site_rules(geosite, ("GEOLOCATION-!CN",), only_cn=True)
    parsed["xray-foreign-categories"] = xray_site_rules(
        geosite,
        (
            "MICROSOFT",
            "NVIDIA",
            "AMD",
            "INTEL",
            "SAMSUNG",
            "NINTENDO",
            "STEAM",
            "EPICGAMES",
            "ADOBE",
            "GOOGLE",
        ),
        only_cn=True,
    )
    # Vendor sites and download endpoints that are commonly reachable
    # directly.  NVIDIA's category also contains Hugging Face, which is
    # filtered by FOREIGN_DIRECT_DENYLIST below.
    parsed["xray-foreign-full"] = xray_site_rules(
        geosite,
        ("AMD", "INTEL", "ADOBE", "SAMSUNG", "NVIDIA"),
    )
    parsed["xray-cn-ip"] = Parsed(geoip.get("CN", []))
    parsed["xray-private-ip"] = Parsed(geoip.get("PRIVATE", []))

    # Guard against silently publishing a truncated source.
    for key, minimum in {
        "loyalsoldier-direct": 100_000,
        "loyalsoldier-cncidr": 9_000,
        "loyalsoldier-apple": 150,
        "loyalsoldier-icloud": 40,
        "loyalsoldier-lancidr": 20,
        "loyalsoldier-private": 100,
        "bm7-chinamax-domain": 100_000,
        "bm7-chinamax-ip": 10_000,
        "bm7-apple-domain": 1_300,
        "bm7-apple": 10,
        "bm7-tesla": 10,
        "karing-cn": 100_000,
        "karing-apple": 1_500,
        "karing-tesla": 10,
        "karing-microsoft-cn": 150,
        "karing-nvidia-cn": 3,
        "karing-cn-ip": 9_000,
        "acl4ssr-china-domain": 500,
        "acl4ssr-china-ip": 5_000,
        "acl4ssr-apple": 20,
        "xray-cn": 5_000,
        "xray-apple": 1_500,
        "xray-tesla": 10,
        "xray-foreign": 500,
        "xray-foreign-full": 250,
        "xray-cn-ip": 8_000,
    }.items():
        require(key, parsed[key].rules, minimum)

    def combine(keys: Iterable[str]) -> list[Rule]:
        rules: set[Rule] = set()
        for key in keys:
            rules.update(parsed[key].rules)
        return dedupe_sorted(rules)

    cn_all = combine(
        (
            "loyalsoldier-direct",
            "karing-cn",
            "bm7-chinamax-domain",
            "xray-cn",
            "acl4ssr-china-domain",
        )
    )
    cn_domains = [rule for rule in cn_all if rule[0] in (2, 3)]
    cn_ip_from_domains = [rule for rule in cn_all if rule[0] in (0, 1)]

    cn_ip_all = set(
        combine(
            (
                "loyalsoldier-cncidr",
                "karing-cn-ip",
                "bm7-chinamax-ip",
                "xray-cn-ip",
                "acl4ssr-china-ip",
            )
        )
    )
    cn_ip_all.update(cn_ip_from_domains)
    cn_ip = dedupe_sorted(rule for rule in cn_ip_all if rule[0] in (0, 1))
    cn_domains = safe_cn_domains(
        dedupe_sorted(cn_domains + [rule for rule in cn_ip_all if rule[0] in (2, 3)])
    )

    apple = safe_direct(
        combine(
            (
                "loyalsoldier-apple",
                "loyalsoldier-icloud",
                "karing-apple",
                "xray-apple",
                "bm7-apple-domain",
                "bm7-apple",
                "acl4ssr-apple",
            )
        )
    )
    tesla = safe_direct(
        combine(
            (
                "karing-tesla",
                "xray-tesla",
                "bm7-tesla",
            )
        )
    )
    foreign = safe_foreign_direct(
        combine(
            (
                "xray-foreign",
                "xray-foreign-categories",
                "xray-foreign-full",
                "karing-microsoft-cn",
                "karing-nvidia-cn",
                "karing-samsung-cn",
                "karing-nintendo-cn",
                "karing-steam-cn",
                "karing-google-cn",
            )
        )
    )
    apple_set = set(apple)
    tesla_set = set(tesla)
    # Keep Foreign-Direct self-contained.  Some entries overlap CN-Domains;
    # both sets use DIRECT, so the overlap is harmless.
    foreign = [rule for rule in foreign if rule not in apple_set and rule not in tesla_set]

    lan = combine(
        (
            "loyalsoldier-lancidr",
            "loyalsoldier-private",
            "karing-private-ip",
            "xray-private-ip",
        )
    )
    steam = dedupe_sorted((2, domain) for domain in STEAM_DOWNLOAD_DOMAINS)

    require("CN domains", cn_domains, 100_000)
    require("CN IP", cn_ip, 12_000)
    require("Apple", apple, 1_500)
    require("Tesla", tesla, 10)
    require("Foreign direct", foreign, 500)
    require("LAN", lan, 100)
    require("Steam download", steam, 16)

    # All generated sets use DIRECT, so they can be merged into one
    # subscription.  Deduplicate across sets to stay well below the 200k cap.
    all_direct = dedupe_sorted(
        set(cn_domains)
        | set(cn_ip)
        | set(apple)
        | set(tesla)
        | set(foreign)
        | set(lan)
        | set(steam)
    )
    require("All direct", all_direct, 100_000)
    if len(all_direct) > MAX_RULES_PER_SET:
        raise RuntimeError(
            f"merged DIRECT set has {len(all_direct)} rules, exceeding the "
            f"{MAX_RULES_PER_SET} rule limit"
        )

    cn_parts = split_even(cn_domains, args.limit, min_parts=2)
    outputs: list[tuple[str, str, list[Rule], str]] = []
    for index, part in enumerate(cn_parts, start=1):
        outputs.append(
            (
                f"CN-Domains-{index}.arrs",
                f"国内域名直连 {index}/{len(cn_parts)}",
                part,
                "Loyalsoldier + blackmatrix7 + Karing + XTLS Xray + ACL4SSR",
            )
        )
    outputs.extend(
        [
            (
                "CN-IP.arrs",
                "国内 IP 直连",
                cn_ip,
                "Loyalsoldier + blackmatrix7 + Karing + XTLS Xray + ACL4SSR",
            ),
            (
                "Apple.arrs",
                "Apple 直连",
                apple,
                "Loyalsoldier + blackmatrix7 + Karing + XTLS Xray + ACL4SSR",
            ),
            (
                "Tesla.arrs",
                "Tesla 直连",
                tesla,
                "blackmatrix7 + Karing + XTLS Xray",
            ),
            (
                "Foreign-Direct.arrs",
                "国外可直连",
                foreign,
                "XTLS Xray geosite @cn + Karing @cn + AMD/Intel/Adobe/Samsung/NVIDIA",
            ),
            (
                "Steam-Direct.arrs",
                "Steam 下载直连",
                steam,
                "Steam download CDN domains",
            ),
            (
                "LAN.arrs",
                "局域网直连",
                lan,
                "Loyalsoldier + Karing + XTLS Xray",
            ),
            (
                "All-Direct.arrs",
                "全部直连（合并订阅）",
                all_direct,
                "Merged CN + Apple + Tesla + Foreign-Direct + Steam-Direct + LAN",
            ),
        ]
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in list(out_dir.glob("*.arrs")) + [
        out_dir / "manifest.json",
        out_dir / "RELEASE_NOTES.md",
        out_dir / "SHA256SUMS",
        out_dir / "status.json",
    ]:
        if stale.exists():
            stale.unlink()

    files: list[dict[str, object]] = []
    for filename, name, rules, source in outputs:
        path = out_dir / filename
        info = write_arrs(path, name, rules, source, generated_at)
        validate_arrs(path, len(rules))
        files.append({**info, "routing": "DIRECT", "source": source})
        print(f"wrote {path} ({len(rules)} rules)", flush=True)

    source_info: dict[str, dict[str, object]] = {}
    for spec in DOWNLOADS:
        data, url = downloaded[spec.key]
        source_info[spec.key] = {
            "label": spec.label,
            "url": url,
            "bytes": len(data),
        }

    parsed_info = {
        key: {
            "rules": len(value.rules),
            "invalid": value.invalid,
            "skipped": value.skipped,
        }
        for key, value in sorted(parsed.items())
    }

    manifest: dict[str, object] = {
        "generated_at": generated_at,
        "release_tag": release_tag,
        "repo": args.repo,
        "split_limit": args.limit,
        "max_rules_per_set": MAX_RULES_PER_SET,
        "sources": source_info,
        "parsed": parsed_info,
        "files": files,
        "groups": {
            "cn_domains": len(cn_domains),
            "cn_ip": len(cn_ip),
            "apple": len(apple),
            "tesla": len(tesla),
            "foreign_direct": len(foreign),
            "steam_download": len(steam),
            "lan": len(lan),
        },
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    checksum_lines = [f"{item['sha256']}  {item['file']}" for item in files]
    (out_dir / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    status = {
        "updated_at": generated_at,
        "release_tag": release_tag,
        "files": {str(item["file"]): item["rules"] for item in files},
    }
    (out_dir / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    base_url = f"https://github.com/{args.repo}/releases/latest/download"
    table = "\n".join(
        f"| `{item['file']}` | {item['rules']:,} | {item['name']} | [订阅]({base_url}/{item['file']}) |"
        for item in files
    )
    notes = f"""# Anywhere 分流规则 {release_date.replace('.', '-')}

每日自动构建。默认国外走代理；国内、Apple、Tesla、国外可直连域名、Steam 下载域名和局域网走 DIRECT。

数据源：[Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)、[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)、[KaringX/karing-ruleset](https://github.com/KaringX/karing-ruleset)、[XTLS/Xray-rules-dat](https://github.com/XTLS/Xray-rules-dat)、[ACL4SSR](https://github.com/ACL4SSR/ACL4SSR)。

## 订阅地址

| 文件 | 条数 | 用途 | 链接 |
| --- | ---: | --- | --- |
{table}

> **只用一个地址：只添加 `All-Direct.arrs`。** 它合并了全部 DIRECT 规则（当前 {len(all_direct):,} 条）。
> 当前 Anywhere 代码允许每套 200,000 条；旧版若仍限制 100,000 条会拒绝，请更新 App 或使用拆分订阅。
>
> 拆分方案：`CN-Domains-1.arrs` 和 `CN-Domains-2.arrs` 必须同时添加。
> `Foreign-Direct.arrs` 只包含 Xray geosite / Karing 标记为 `@cn` 的国外域名，以及 AMD/Intel/Adobe/Samsung/NVIDIA 等常见厂商分类；GitHub、Hugging Face 等仍走代理。
> `Steam-Direct.arrs` 只包含游戏下载 CDN（`steamcontent.com`、`steamserver.net`、`cm.steampowered.com` 等）；Steam 商店、社区、登录等其它 Steam 域名仍走默认代理。

## 在 Anywhere 中配置

1. 路由模式选择 **Rule**，默认路由选择你的代理节点或代理链。
2. `Routing → Country Bypass` 选择 **中国 (CN)**。
3. 添加上表全部 `.arrs` 订阅，动作全部设置为 **DIRECT**。
4. 内置服务规则保持 **Default**，不要批量指派 PROXY。
5. 如需广告拦截，把 `ADBlock` 设置为 **REJECT**。
6. 如果开启了 **Prevent DNS Leak**，未匹配的国内域名不会再按解析 IP 回退到 Country Bypass，必须依赖完整的 `CN-Domains` 列表。

## 本次构建

- 生成时间：`{generated_at}`
- 国内域名：{len(cn_domains):,} 条，拆成 {len(cn_parts)} 个文件
- 国内 IP：{len(cn_ip):,} 条
- Apple / iCloud：{len(apple):,} 条
- Tesla：{len(tesla):,} 条
- 国外可直连：{len(foreign):,} 条
- Steam 下载直连：{len(steam):,} 条
- 局域网：{len(lan):,} 条
- Steam 商店、社区、登录等非下载域名不会进入 DIRECT 集合
- DNS 泄漏测试域名（`browserleaks.com`、`dnsleaktest.com`、`ipleak.net` 等）不会进入 DIRECT 集合

规则文件只声明匹配范围；动作需要在 Anywhere 里按上表指派。文件的 `routing = 1` 只在首次导入时作为 DIRECT 的初始值，订阅刷新不会覆盖本地动作。

## 文件校验

`SHA256SUMS` 和 `manifest.json` 随 Release 一起发布。
"""
    (out_dir / "RELEASE_NOTES.md").write_text(notes, encoding="utf-8")

    print(
        f"done: {len(files)} files, {sum(len(rules) for _, _, rules, _ in outputs):,} rules",
        flush=True,
    )
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="dist", help="output directory (default: dist)")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO),
        help="owner/repo used in release links",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_SPLIT_LIMIT,
        help=f"maximum rules per file (default: {DEFAULT_SPLIT_LIMIT})",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="cache downloaded sources in this directory",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="ignore cached sources and download again",
    )
    parser.add_argument("--attempts", type=int, default=2, help="download attempts per mirror")
    parser.add_argument("--timeout", type=int, default=60, help="download timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.limit > MAX_RULES_PER_SET:
        print(f"error: --limit cannot exceed {MAX_RULES_PER_SET}", file=sys.stderr)
        return 2
    try:
        build(args)
    except Exception as exc:  # noqa: BLE001 - top-level CLI error reporting
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
