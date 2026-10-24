import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import boundary_map as bm

EXAMPLE = ROOT / "examples/fictional-payments"
REPORT = EXAMPLE / "report.json"


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.report = bm.read_json(REPORT)

    def errors(self):
        return bm.validate(self.report, REPORT, EXAMPLE)

    def test_complete_example_and_rendered_output(self):
        self.assertEqual([], self.errors())
        self.assertEqual((EXAMPLE / "REPORT.md").read_text(), bm.render(self.report))

    def test_hash_detects_changed_evidence(self):
        self.report["evidence"][0]["sha256"] = "0" * 64
        self.assertTrue(any("hash does not match" in e for e in self.errors()))

    def test_rejects_invalid_line_ranges(self):
        self.report["evidence"][0]["end_line"] = 10000
        self.assertTrue(any("Invalid line range" in e for e in self.errors()))

    def test_rejects_path_traversal_and_absolute_paths(self):
        for path in ("../README.md", str(ROOT / "README.md")):
            with self.subTest(path=path):
                self.report["evidence"][0]["path"] = path
                self.assertTrue(any("must be relative" in e for e in self.errors()))

    def test_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "repo"
            root.mkdir()
            outside = Path(folder) / "outside.txt"
            outside.write_text("secret\n")
            (root / "escape.txt").symlink_to(outside)
            with self.assertRaisesRegex(bm.ReportError, "escapes"):
                bm.evidence_record(root, "escape.txt", 1, 1, "E1")

    def test_missing_and_duplicate_references(self):
        self.report["steps"][0]["boundary_ids"] = ["NO_SUCH_BOUNDARY"]
        self.report["evidence"].append(copy.deepcopy(self.report["evidence"][0]))
        errors = self.errors()
        self.assertTrue(any("unknown reference" in e for e in errors))
        self.assertTrue(any("duplicate IDs" in e for e in errors))

    def test_external_policy_with_attacker_admin_cannot_survive(self):
        self.report["boundaries"][0]["status"] = "survives"
        self.assertTrue(any("attacker-controlled" in e for e in self.errors()))

    def test_unknown_change_authority_cannot_survive(self):
        self.report["boundaries"][1]["change_paths"][0]["attacker_control"] = "unknown"
        self.assertTrue(any("unresolved change authority" in e for e in self.errors()))

    def test_deployment_conclusion_needs_snapshot(self):
        self.report["boundaries"][1]["evidence_basis"] = "deployment_snapshot"
        self.assertTrue(any("requires referenced deployment snapshot" in e for e in self.errors()))

    def test_snapshot_needs_timestamp_and_provenance(self):
        self.report["evidence"][0]["kind"] = "deployment_snapshot"
        self.report["evidence"][0]["captured_at"] = "2026-10-23T12:00:00"
        self.assertTrue(any("timestamp with timezone" in e for e in self.errors()))

    def test_source_only_conclusion_needs_production_checks(self):
        self.report["boundaries"][1]["production_checks"] = []
        self.assertTrue(any("requires production checks" in e for e in self.errors()))

    def test_each_boundary_requires_challenge(self):
        self.report["challenges"] = self.report["challenges"][:-1]
        self.assertTrue(any("missing challenge pass" in e for e in self.errors()))

    def test_unverified_needs_open_question(self):
        self.report["open_questions"] = []
        self.assertTrue(any("needs an open question" in e for e in self.errors()))

    def test_schema_rejects_missing_fields_and_wrong_types(self):
        del self.report["scope"]["operation"]
        self.report["evidence"][0]["start_line"] = True
        self.report["unexpected"] = "ignored?"
        errors = self.errors()
        self.assertTrue(any("operation: required" in e for e in errors))
        self.assertTrue(any("expected integer" in e for e in errors))
        self.assertTrue(any("unknown field" in e for e in errors))

    def test_render_escapes_html_and_table_delimiters(self):
        self.report["boundaries"][0]["restriction"] = "<script>alert(1)</script>|fake"
        rendered = bm.render(self.report)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("\\|fake", rendered)


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "boundary_map.py"), *map(str, args)],
                              text=True, capture_output=True, timeout=10)

    def test_init_creates_incomplete_review_without_overwriting(self):
        with tempfile.TemporaryDirectory(prefix="boundary map ") as folder:
            out = Path(folder) / "private review"
            args = ["init", "--repo", EXAMPLE, "--operation", "withdrawal", "--compromised", "API", "--out", out]
            result = self.run_cli(*args)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("withdrawal", bm.read_json(out / "scope.json")["operation"])
            self.assertIn("No investigation has run", result.stdout)
            self.assertTrue((out / "RUN.md").exists())
            self.assertTrue((out / "CHALLENGE.md").exists())
            invalid = self.run_cli("validate", out / "report.json", "--repo", EXAMPLE)
            self.assertEqual(1, invalid.returncode)
            original = (out / "scope.json").read_bytes()
            self.assertEqual(2, self.run_cli(*args).returncode)
            self.assertEqual(original, (out / "scope.json").read_bytes())

    def test_evidence_validate_render_end_to_end(self):
        record = self.run_cli("evidence", "--root", EXAMPLE, "--path", "src/withdrawal.py",
                              "--start", 4, "--end", 8, "--id", "E1")
        self.assertEqual(0, record.returncode, record.stderr)
        self.assertEqual(bm.read_json(REPORT)["evidence"][0], json.loads(record.stdout))
        valid = self.run_cli("validate", REPORT, "--repo", EXAMPLE)
        self.assertEqual(0, valid.returncode, valid.stderr)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "review.md"
            rendered = self.run_cli("render", REPORT, "--repo", EXAMPLE, "--out", output)
            self.assertEqual(0, rendered.returncode, rendered.stderr)
            self.assertEqual((EXAMPLE / "REPORT.md").read_text(), output.read_text())
            self.assertEqual(2, self.run_cli("render", REPORT, "--repo", EXAMPLE, "--out", output).returncode)

    def test_invalid_json_fails_with_useful_message(self):
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / "report.json"
            bad.write_text("{not json")
            result = self.run_cli("validate", bad, "--repo", EXAMPLE)
            self.assertEqual(2, result.returncode)
            self.assertIn("Cannot read JSON", result.stderr)


if __name__ == "__main__":
    unittest.main()
