import importlib.util
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

    def test_invalid(self):
        self.assertIsNone(build.to_rule("bad domain"))
        self.assertIsNone(build.to_rule(""))
        self.assertIsNone(build.to_rule("-bad.example.com"))


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
