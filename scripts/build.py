#!/usr/bin/env python3
"""Build Anywhere .arrs rule sets from Loyalsoldier/clash-rules.

The generated sets implement a China-direct routing layout:

  * default route -> proxy
  * CN-Domains-*.arrs, CN-IP.arrs, Apple.arrs, LAN.arrs -> DIRECT

Only the Python standard library is required.
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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_REPO = "lhxyzCJ/anywhere-proxy-rule"
USER_AGENT = "anywhere-proxy-rule/1.0 (+https://github.com/lhxyzCJ/anywhere-proxy-rule)"

MIRRORS = (
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/",
    "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/",
    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/",
)

MAX_RULES_PER_SET = 100_000
DEFAULT_SPLIT_LIMIT = 90_000
CHINA_TZ = timezone(timedelta(hours=8))


@dataclass(frozen=True)
class Source:
    filename: str
    min_count: int
    label: str


SOURCES = {
    "direct": Source("direct.txt", 95_000, "国内域名"),
    "cncidr": Source("cncidr.txt", 9_000, "国内 IP"),
    "apple": Source("apple.txt", 150, "Apple"),
    "icloud": Source("icloud.txt", 40, "iCloud"),
    "lancidr": Source("lancidr.txt", 20, "局域网 CIDR"),
    "private": Source("private.txt", 100, "路由器/本地域名"),
}

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class Output:
    filename: str
    name: str
    rules: list[tuple[int, str]]
    source: str


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
            # ``payload:`` and other YAML section headers.
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

    if any(ord(char) > 127 for char in value):
        try:
            value = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None

    labels = value.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels):
        return None
    return value


def to_rule(value: str) -> tuple[int, str] | None:
    """Convert one source entry to an Anywhere ``(type, value)`` rule."""
    value = value.strip().strip("'\"").strip()
    if not value:
        return None

    # CIDR or a bare IP address. A bare address becomes /32 or /128.
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        pass
    else:
        rule_type = 0 if network.version == 4 else 1
        return rule_type, str(network)

    domain = normalize_domain(value)
    if domain:
        return 2, domain
    return None


def rule_sort_key(rule: tuple[int, str]) -> tuple[int, str]:
    return rule[0], rule[1]


def convert(values: list[str], label: str) -> tuple[list[tuple[int, str]], int]:
    rules: set[tuple[int, str]] = set()
    invalid = 0
    for value in values:
        rule = to_rule(value)
        if rule is None:
            invalid += 1
        else:
            rules.add(rule)
    if invalid > max(10, len(values) // 50):
        raise RuntimeError(
            f"{label}: {invalid}/{len(values)} entries could not be parsed; "
            "refusing to publish a partially converted set"
        )
    return sorted(rules, key=rule_sort_key), invalid


def split_even(
    rules: list[tuple[int, str]], limit: int, min_parts: int = 2
) -> list[list[tuple[int, str]]]:
    """Split into balanced, stable parts, each no larger than ``limit``."""
    if not rules:
        raise RuntimeError("cannot split an empty rule set")
    if limit < 1 or limit > MAX_RULES_PER_SET:
        raise ValueError(f"split limit must be between 1 and {MAX_RULES_PER_SET}")

    part_count = max(min_parts, math.ceil(len(rules) / limit))
    part_size = math.ceil(len(rules) / part_count)
    return [rules[index : index + part_size] for index in range(0, len(rules), part_size)]


def fetch_source(
    source: Source,
    source_dir: Path | None,
    attempts: int,
    timeout: int,
) -> tuple[list[str], str]:
    if source_dir is not None:
        path = source_dir / source.filename
        text = path.read_text(encoding="utf-8")
        values = parse_payload(text)
        if len(values) < source.min_count:
            raise RuntimeError(
                f"{path}: only {len(values)} entries, expected at least {source.min_count}"
            )
        return values, str(path)

    errors: list[str] = []
    for attempt in range(1, attempts + 1):
        for base in MIRRORS:
            url = base + source.filename
            try:
                request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    if response.status != 200:
                        raise RuntimeError(f"HTTP {response.status}")
                    body = response.read()
                values = parse_payload(body.decode("utf-8"))
                if len(values) < source.min_count:
                    raise RuntimeError(
                        f"only {len(values)} entries, expected at least {source.min_count}"
                    )
                return values, url
            except Exception as exc:  # noqa: BLE001 - mirror fallback is intentional
                errors.append(f"{url}: {type(exc).__name__}: {exc}")
                print(f"  ! {url} ({type(exc).__name__})", file=sys.stderr)
        if attempt < attempts:
            time.sleep(attempt * 2)

    raise RuntimeError(
        f"failed to download {source.filename} from every mirror:\n"
        + "\n".join(errors[-6:])
    )


def write_arrs(
    path: Path,
    name: str,
    rules: list[tuple[int, str]],
    source_note: str,
    generated_at: str,
) -> dict[str, object]:
    lines = [
        f"name = {name}",
        "routing = 1",
        f"# Generated at {generated_at}",
        f"# Source: {source_note}",
        f"# Rule types: 0 IPv4 CIDR, 1 IPv6 CIDR, 2 domain suffix, 3 domain keyword",
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
    seen: set[tuple[int, str]] = set()

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


def build(args: argparse.Namespace) -> dict[str, object]:
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    release_date = now_utc.astimezone(CHINA_TZ).strftime("%Y.%m.%d")
    generated_at = now_utc.isoformat().replace("+00:00", "Z")
    release_tag = "rules-" + release_date

    raw: dict[str, list[str]] = {}
    source_info: dict[str, dict[str, object]] = {}
    for key, source in SOURCES.items():
        print(f"fetch {source.filename} ({source.label}) ...", flush=True)
        values, url = fetch_source(
            source,
            args.source_dir,
            attempts=args.attempts,
            timeout=args.timeout,
        )
        raw[key] = values
        source_info[key] = {"url": url, "entries": len(values)}
        print(f"  {len(values)} entries", flush=True)

    direct_rules, direct_invalid = convert(raw["direct"], "direct.txt")
    cn_domain_rules = [rule for rule in direct_rules if rule[0] == 2]
    direct_ip_rules = [rule for rule in direct_rules if rule[0] != 2]

    cn_ip_rules, cncidr_invalid = convert(raw["cncidr"], "cncidr.txt")
    cn_ip_rules = sorted(set(cn_ip_rules) | set(direct_ip_rules), key=rule_sort_key)

    apple_rules, apple_invalid = convert(raw["apple"] + raw["icloud"], "apple.txt + icloud.txt")
    lan_rules, lan_invalid = convert(raw["lancidr"] + raw["private"], "lancidr.txt + private.txt")

    minimums = {
        "CN domains": (cn_domain_rules, 95_000),
        "CN IP": (cn_ip_rules, 9_000),
        "Apple": (apple_rules, 150),
        "LAN": (lan_rules, 100),
    }
    for label, (rules, minimum) in minimums.items():
        if len(rules) < minimum:
            raise RuntimeError(f"{label}: only {len(rules)} rules, expected at least {minimum}")

    cn_parts = split_even(cn_domain_rules, args.limit, min_parts=2)
    outputs: list[Output] = []
    for index, part in enumerate(cn_parts, start=1):
        outputs.append(
            Output(
                filename=f"CN-Domains-{index}.arrs",
                name=f"国内域名直连 {index}/{len(cn_parts)}",
                rules=part,
                source="Loyalsoldier/clash-rules direct.txt",
            )
        )
    outputs.extend(
        [
            Output(
                filename="CN-IP.arrs",
                name="国内 IP 直连",
                rules=cn_ip_rules,
                source="Loyalsoldier/clash-rules cncidr.txt",
            ),
            Output(
                filename="Apple.arrs",
                name="Apple 直连",
                rules=apple_rules,
                source="Loyalsoldier/clash-rules apple.txt + icloud.txt",
            ),
            Output(
                filename="LAN.arrs",
                name="局域网直连",
                rules=lan_rules,
                source="Loyalsoldier/clash-rules lancidr.txt + private.txt",
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
    for output in outputs:
        path = out_dir / output.filename
        info = write_arrs(
            path,
            output.name,
            output.rules,
            output.source,
            generated_at,
        )
        validate_arrs(path, len(output.rules))
        files.append(
            {
                **info,
                "routing": "DIRECT",
                "source": output.source,
            }
        )
        print(f"wrote {path} ({len(output.rules)} rules)", flush=True)

    manifest: dict[str, object] = {
        "generated_at": generated_at,
        "release_tag": release_tag,
        "repo": args.repo,
        "split_limit": args.limit,
        "max_rules_per_set": MAX_RULES_PER_SET,
        "sources": source_info,
        "files": files,
        "invalid_entries": {
            "direct": direct_invalid,
            "cncidr": cncidr_invalid,
            "apple+icloud": apple_invalid,
            "lancidr+private": lan_invalid,
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

每日自动构建，数据源为 [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)。

## 订阅地址

| 文件 | 条数 | 用途 | 链接 |
| --- | ---: | --- | --- |
{table}

> `CN-Domains-1.arrs` 和 `CN-Domains-2.arrs` 必须同时添加，两个文件合起来才是完整的国内域名列表。

## 在 Anywhere 中配置

1. 路由模式选择 **Rule**，默认路由选择你的代理节点或代理链。
2. `Routing → Country Bypass` 选择 **中国 (CN)**。
3. 添加上表全部 `.arrs` 订阅，动作全部设置为 **DIRECT**。
4. 内置服务规则保持 **Default**，不要批量指派 PROXY。
5. 如需广告拦截，把 `ADBlock` 设置为 **REJECT**。
6. 如果开启了 **Prevent DNS Leak**，未匹配的国内域名不会再按解析 IP 回退到 Country Bypass，必须依赖完整的 `CN-Domains` 列表。

## 本次构建

- 生成时间：`{generated_at}`
- 国内域名：{len(cn_domain_rules):,} 条，拆成 {len(cn_parts)} 个文件
- 国内 IP：{len(cn_ip_rules):,} 条
- Apple / iCloud：{len(apple_rules):,} 条
- 局域网：{len(lan_rules):,} 条

规则文件只声明匹配范围；动作需要在 Anywhere 里按上表指派。文件的 `routing = 1` 只在首次导入时作为 DIRECT 的初始值，订阅刷新不会覆盖本地动作。

## 文件校验

`SHA256SUMS` 和 `manifest.json` 随 Release 一起发布。
"""
    (out_dir / "RELEASE_NOTES.md").write_text(notes, encoding="utf-8")

    print(
        f"done: {len(files)} files, {sum(len(output.rules) for output in outputs):,} rules",
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
        "--source-dir",
        type=Path,
        default=None,
        help="read source .txt files from this directory instead of downloading",
    )
    parser.add_argument("--attempts", type=int, default=2, help="download attempts per mirror")
    parser.add_argument("--timeout", type=int, default=45, help="download timeout in seconds")
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
