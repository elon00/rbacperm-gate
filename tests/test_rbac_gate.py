"""Real, negative-heavy offline RBAC regression tests (not authentication tests)."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rbac_gate import InvalidPolicy, decide_bytes, evaluate, MAX_BYTES


def policy():
    return {
        "roles": {
            "reader": {"allow": ["document.read"], "deny": [], "inherits": []},
            "editor": {"allow": ["document.write"], "deny": [], "inherits": ["reader"]},
            "blocked": {"allow": [], "deny": ["document.read"], "inherits": []},
        },
        "subjects": {"alice": ["editor"], "bob": ["reader"], "carol": ["editor", "blocked"]},
        "request": {"subject": "alice", "permission": "document.read"},
    }


class RbacGateTests(unittest.TestCase):
    def test_inherited_allow(self):
        self.assertTrue(evaluate(policy()))

    def test_direct_allow(self):
        p = policy(); p["request"]["permission"] = "document.write"
        self.assertTrue(evaluate(p))

    def test_deny_by_default(self):
        p = policy(); p["request"]["permission"] = "document.delete"
        self.assertFalse(evaluate(p))

    def test_explicit_deny_overrides_allow(self):
        p = policy(); p["request"]["subject"] = "carol"
        self.assertFalse(evaluate(p))

    def test_unknown_subject_denied(self):
        p = policy(); p["request"]["subject"] = "nobody"
        self.assertFalse(evaluate(p))

    def test_unknown_role_fails_closed(self):
        p = policy(); p["subjects"]["alice"] = ["admin"]
        with self.assertRaises(InvalidPolicy): evaluate(p)

    def test_inheritance_cycle_fails_closed(self):
        p = policy(); p["roles"]["reader"]["inherits"] = ["editor"]
        with self.assertRaises(InvalidPolicy): evaluate(p)

    def test_self_cycle_fails_closed(self):
        p = policy(); p["roles"]["reader"]["inherits"] = ["reader"]
        with self.assertRaises(InvalidPolicy): evaluate(p)

    def test_duplicate_json_key_rejected(self):
        raw = b'{"roles":{},"roles":{},"subjects":{},"request":{"subject":"alice","permission":"read"}}'
        with self.assertRaises(InvalidPolicy): decide_bytes(raw)

    def test_duplicate_permission_rejected(self):
        p = policy(); p["roles"]["reader"]["allow"].append("document.read")
        with self.assertRaises(InvalidPolicy): evaluate(p)

    def test_wildcard_rejected(self):
        p = policy(); p["roles"]["reader"]["allow"] = ["*"]
        with self.assertRaises(InvalidPolicy): evaluate(p)

    def test_extra_field_rejected(self):
        p = policy(); p["admin"] = True
        with self.assertRaises(InvalidPolicy): evaluate(p)

    def test_invalid_utf8_rejected(self):
        with self.assertRaises(InvalidPolicy): decide_bytes(b'\xff')

    def test_oversized_payload_rejected(self):
        with self.assertRaises(InvalidPolicy): decide_bytes(b' ' * (MAX_BYTES + 1))

    def test_invalid_numeric_constant_rejected(self):
        raw = json.dumps(policy()).replace('"document.read"', 'NaN', 1).encode()
        with self.assertRaises(InvalidPolicy): decide_bytes(raw)

    def test_cli_allows_and_denies(self):
        script = Path(__file__).resolve().parents[1] / 'rbac_gate.py'
        p = policy()
        for permission, expected in [("document.read", True), ("document.delete", False)]:
            p["request"]["permission"] = permission
            proc = subprocess.run([sys.executable, str(script)], input=json.dumps(p).encode(), capture_output=True, timeout=5)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["authorized"], expected)

    def test_cli_fails_closed_on_invalid_json(self):
        script = Path(__file__).resolve().parents[1] / 'rbac_gate.py'
        proc = subprocess.run([sys.executable, str(script)], input=b'{broken', capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(json.loads(proc.stdout)["authorized"])


if __name__ == '__main__':
    unittest.main()
