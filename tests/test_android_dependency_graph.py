"""Synthetic Gradle outputs: independent dependency graph / partial BOM audit tests."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "audit_android_dependency_graph.py"
spec = importlib.util.spec_from_file_location("android_dependency_graph_audit", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

RUNTIME = """\
> Task :app:dependencies
debugRuntimeClasspath - Runtime classpath of debug.
+--- org.jetbrains.kotlin:kotlin-stdlib:2.3.21
|    \\--- org.jetbrains:annotations:13.0
BUILD SUCCESSFUL in 3s
"""
TEST = """\
> Task :app:dependencies
debugUnitTestRuntimeClasspath - Resolved configuration for debug unit test.
+--- junit:junit:4.13.2
|    \\--- org.hamcrest:hamcrest-core:1.3
+--- org.jetbrains.kotlin:kotlin-stdlib:2.3.21
|    \\--- org.jetbrains:annotations:13.0
BUILD SUCCESSFUL in 3s
"""


NOTICE = """# Third-party notices — REVIEW INCOMPLETE

NOT a full SBOM.

| Package | Scope | License metadata |
| --- | --- | --- |
| \x60pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.3.21\x60 | debug runtime | Apache-2.0 (NOT VERIFIED) |
| \x60pkg:maven/org.jetbrains/annotations@13.0\x60 | debug runtime | Apache-2.0 (NOT VERIFIED) |
| \x60pkg:maven/junit/junit@4.13.2\x60 | JVM tests ONLY | EPL-1.0 (review OPEN) |
| \x60pkg:maven/org.hamcrest/hamcrest-core@1.3\x60 | JVM tests ONLY | New BSD (review OPEN) |
"""


class DependencyGraphAuditTests(unittest.TestCase):
    def test_complete_scoped_graph_reports_partial_non_release(self):
        data = mod.audit(RUNTIME, TEST)
        self.assertEqual(data["graphAudit"], "PASS")
        self.assertEqual(data["inventoryCompleteness"], "PARTIAL")
        self.assertEqual(data["licenseClosure"], "NOT_VERIFIED")
        self.assertFalse(data["releaseApproved"])
        self.assertFalse(data["pluginClasspathCovered"])
        self.assertEqual(data["componentCounts"], {"runtime": 2, "test": 4})
        self.assertEqual(data["testComponents"][0]["licenseEvidence"],
                         "EPL-1.0 (supplier POM; test-only boundary)")

    def test_missing_required_test_module_fails(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME, TEST.replace("junit:junit:4.13.2", "other:module:1.0"))

    def test_junit_in_android_runtime_fails(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME.replace("BUILD SUCCESSFUL", "+--- junit:junit:4.13.2\nBUILD SUCCESSFUL"), TEST)

    def test_unpinned_junit_version_fails(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME, TEST.replace("junit:junit:4.13.2", "junit:junit:4.13.1"))

    def test_dynamic_version_fails(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME.replace("kotlin-stdlib:2.3.21", "kotlin-stdlib:2.+"), TEST)

    def test_failed_resolution_fails(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME.replace("BUILD SUCCESSFUL", "BUILD FAILED"), TEST)

    def test_unresolved_module_fails(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME.replace("BUILD SUCCESSFUL", "+--- example:module:1.2 FAILED\nBUILD SUCCESSFUL"), TEST)

    def test_gradle_could_not_resolve_edge_fails(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME.replace(
                "BUILD SUCCESSFUL", "Could not resolve artifact\\nBUILD SUCCESSFUL"), TEST)

    def test_missing_configuration_fails(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME.replace("debugRuntimeClasspath", "compileClasspath"), TEST)

    def test_conflicting_versions_fail(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME.replace("BUILD SUCCESSFUL", "+--- org.jetbrains.kotlin:kotlin-stdlib:2.3.20\nBUILD SUCCESSFUL"), TEST)

    def test_gradle_requested_version_resolution_is_recorded(self):
        data = mod.audit(RUNTIME, TEST.replace("junit:junit:4.13.2", "junit:junit:4.13.1 -> 4.13.2"))
        self.assertIn("pkg:maven/junit/junit@4.13.2", [c["purl"] for c in data["testComponents"]])

    def test_unreviewed_module_is_included_not_auto_licensed(self):
        data = mod.audit(RUNTIME.replace("BUILD SUCCESSFUL", "+--- vendor:unknown:5.0\nBUILD SUCCESSFUL"), TEST)
        record = next(c for c in data["runtimeComponents"] if c["purl"] == "pkg:maven/vendor/unknown@5.0")
        self.assertEqual(record["licenseEvidence"], "NOT_VERIFIED")
        self.assertFalse(record["licenseApproved"])

    def test_input_bounds_and_symlink_fail_closed(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime.txt"
            test = root / "test.txt"
            runtime.write_text(RUNTIME)
            test.write_text(TEST)
            notice = root / "THIRD-PARTY-NOTICES.md"
            notice.write_text(NOTICE)
            self.assertEqual(mod.main(["--runtime", str(runtime), "--test", str(test),
                                       "--notice", str(notice)]), 0)
            runtime.unlink()
            runtime.symlink_to("/etc/hosts")
            self.assertEqual(mod.main(["--runtime", str(runtime), "--test", str(test),
                                       "--notice", str(notice)]), 2)

    def test_correct_scoped_notice_has_no_license_approval(self):
        data = mod.audit(RUNTIME, TEST)
        mod.check_partial_notice(data, NOTICE)
        self.assertFalse(data["releaseApproved"])
        self.assertEqual(data["licenseClosure"], "NOT_VERIFIED")

    def test_missing_runtime_notice_entry_rejected(self):
        data = mod.audit(RUNTIME, TEST)
        changed = "\n".join(line for line in NOTICE.splitlines()
                            if "kotlin-stdlib@2.3.21" not in line)
        with self.assertRaises(mod.AuditError):
            mod.check_partial_notice(data, changed)

    def test_incorrect_junit_license_notice_rejected(self):
        data = mod.audit(RUNTIME, TEST)
        with self.assertRaises(mod.AuditError):
            mod.check_partial_notice(data, NOTICE.replace("EPL-1.0", "MIT"))

    def test_new_unreviewed_runtime_dependency_rejected(self):
        runtime = RUNTIME.replace("BUILD SUCCESSFUL",
                                  "+--- vendor:unreviewed:1.0\nBUILD SUCCESSFUL")
        data = mod.audit(runtime, TEST)
        with self.assertRaises(mod.AuditError):
            mod.check_partial_notice(data, NOTICE)

    def test_notice_without_partial_disclaimer_rejected(self):
        data = mod.audit(RUNTIME, TEST)
        with self.assertRaises(mod.AuditError):
            mod.check_partial_notice(data, NOTICE.replace("NOT a full SBOM", "ALL LICENSES APPROVED"))

    def test_no_test_tree_cannot_pass(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(RUNTIME, "debugUnitTestRuntimeClasspath - Runtime\nNo dependencies\nBUILD SUCCESSFUL in 0s\n")


if __name__ == "__main__":
    unittest.main()
