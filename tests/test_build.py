import importlib.util
import json
import sys
import unittest
from pathlib import Path

BUILD_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build.py"
SPEC = importlib.util.spec_from_file_location("build", BUILD_PATH)
assert SPEC and SPEC.loader
build = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = build
SPEC.loader.exec_module(build)


class PayloadTests(unittest.TestCase):
    def test_clash_payload(self):
        text = """payload:
  - 'example.com'
  - '+.example.org'
  - "1.2.3.4/24"
"""
        self.assertEqual(
            build.parse_payload(text),
            ["example.com", "+.example.org", "1.2.3.4/24"],
        )

    def test_plain_list(self):
        self.assertEqual(build.parse_payload("# c\n\na.com\nb.com\n"), ["a.com", "b.com"])


class RuleTests(unittest.TestCase):
    def test_domain_suffix(self):
        self.assertEqual(build.to_rule("+.Example.COM."), (2, "example.com"))
        self.assertEqual(build.to_rule("*.example.com"), (2, "example.com"))
        self.assertEqual(build.to_rule("cn"), (2, "cn"))

    def test_idn(self):
        self.assertEqual(build.to_rule("例子.中国"), (2, "xn--fsqu00a.xn--fiqs8s"))

    def test_ipv4_cidr(self):
        self.assertEqual(build.to_rule("1.2.3.4/24"), (0, "1.2.3.0/24"))
        self.assertEqual(build.to_rule("192.168.1.1"), (0, "192.168.1.1/32"))

    def test_ipv6(self):
        self.assertEqual(build.to_rule("2001:db8::1"), (1, "2001:db8::1/128"))

    def test_ipv4_mapped_ipv6(self):
        self.assertEqual(build.to_rule("::ffff:1.2.3.4"), (0, "1.2.3.4/32"))

    def test_invalid(self):
        self.assertIsNone(build.to_rule("bad domain"))
        self.assertIsNone(build.to_rule(""))
        self.assertIsNone(build.to_rule("-bad.example.com"))
        self.assertIsNone(build.to_rule("c"))

    def test_privacy_test_domains_are_not_direct(self):
        rules = [
            (2, "browserleaks.com"),
            (2, "www.browserleaks.com"),
            (2, "browserleaks.io"),
            (2, "example.cn"),
            (2, "cn"),
            (2, "com"),
        ]
        self.assertEqual(
            build.safe_cn_domains(rules),
            [(2, "example.cn"), (2, "cn")],
        )
        self.assertEqual(
            build.safe_direct([(2, "dnsleaktest.com"), (2, "apple.com")]),
            [(2, "apple.com")],
        )


class ParserTests(unittest.TestCase):
    def test_clash_rules(self):
        parsed = build.parse_clash(
            "payload:\n"
            "  - DOMAIN-SUFFIX,example.com\n"
            "  - DOMAIN-KEYWORD,example\n"
            "  - IP-CIDR,1.2.3.0/24,no-resolve\n"
            "  - PROCESS-NAME,Example\n"
        )
        self.assertEqual(
            parsed.rules,
            [(2, "example.com"), (3, "example"), (0, "1.2.3.0/24")],
        )
        self.assertEqual(parsed.invalid, 1)

    def test_karing_json(self):
        payload = {
            "version": 2,
            "rules": [
                {
                    "domain": ["example.com"],
                    "domain_suffix": ["+.example.org", "c"],
                    "domain_keyword": ["sample"],
                    "ip_cidr": ["1.2.3.0/24"],
                    "domain_regex": ["^regex$"],
                    "process_name": ["Example"],
                }
            ],
        }
        parsed = build.parse_karing_json(json.dumps(payload).encode())
        self.assertIn((0, "1.2.3.0/24"), parsed.rules)
        self.assertIn((2, "example.com"), parsed.rules)
        self.assertIn((2, "example.org"), parsed.rules)
        self.assertIn((3, "sample"), parsed.rules)
        self.assertEqual(parsed.skipped, 2)
        self.assertEqual(parsed.invalid, 1)

    def test_xray_geosite(self):
        def varint(value):
            result = bytearray()
            while True:
                byte = value & 0x7F
                value >>= 7
                if value:
                    result.append(byte | 0x80)
                else:
                    result.append(byte)
                    return bytes(result)

        def field(number, wire, payload):
            key = varint((number << 3) | wire)
            if wire == 0:
                return key + varint(payload)
            return key + varint(len(payload)) + payload

        attribute = field(1, 2, b"cn") + field(2, 0, 1)
        domain = field(1, 0, 2) + field(2, 2, b"example.com") + field(3, 2, attribute)
        regex = field(1, 0, 1) + field(2, 2, b"^regex$")
        site = field(1, 2, b"TEST") + field(2, 2, domain) + field(2, 2, regex)
        data = field(1, 2, site)

        sites = build.parse_xray_geosite(data)
        self.assertEqual(sites["TEST"][0][:2], (2, "example.com"))
        parsed = build.xray_site_rules(sites, ("TEST",), only_cn=True)
        self.assertEqual(parsed.rules, [(2, "example.com")])
        self.assertEqual(parsed.skipped, 1)

    def test_xray_geoip(self):
        def varint(value):
            result = bytearray()
            while True:
                byte = value & 0x7F
                value >>= 7
                if value:
                    result.append(byte | 0x80)
                else:
                    result.append(byte)
                    return bytes(result)

        def field(number, wire, payload):
            key = varint((number << 3) | wire)
            if wire == 0:
                return key + varint(payload)
            return key + varint(len(payload)) + payload

        cidr = field(1, 2, bytes([1, 2, 3, 0])) + field(2, 0, 24)
        entry = field(1, 2, b"CN") + field(2, 2, cidr)
        data = field(1, 2, entry)
        self.assertEqual(build.parse_xray_geoip(data)["CN"], [(0, "1.2.3.0/24")])


class SplitTests(unittest.TestCase):
    def test_split_is_balanced_and_within_limit(self):
        rules = [(2, f"d{i}.example.com") for i in range(110_138)]
        parts = build.split_even(rules, 90_000, min_parts=2)
        self.assertEqual(len(parts), 2)
        self.assertTrue(all(len(part) <= 90_000 for part in parts))
        self.assertEqual(sum(len(part) for part in parts), len(rules))

    def test_small_set_still_has_two_parts(self):
        rules = [(2, f"d{i}.example.com") for i in range(10)]
        parts = build.split_even(rules, 90_000, min_parts=2)
        self.assertEqual(len(parts), 2)
        self.assertEqual(len(parts[0]), 5)

    def test_large_set_splits_into_three(self):
        rules = [(2, f"d{i}.example.com") for i in range(190_000)]
        parts = build.split_even(rules, 90_000, min_parts=2)
        self.assertEqual(len(parts), 3)
        self.assertTrue(all(len(part) <= 90_000 for part in parts))


class ValidateTests(unittest.TestCase):
    def test_validate_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.arrs"
            build.write_arrs(
                path,
                "test",
                [(2, "example.com"), (0, "10.0.0.0/8")],
                "unit test",
                "2026-01-01T00:00:00Z",
            )
            build.validate_arrs(path, 2)


if __name__ == "__main__":
    unittest.main()
