"""Offline synthetic Gradle buildEnvironment parser regression fixtures."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "audit_gradle_plugin_graph.py"
spec = importlib.util.spec_from_file_location("gradle_plugin_audit", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

FIXTURE = """\
> Task :buildEnvironment

classpath
+--- com.android.tools.build:gradle:8.13.2
|    \--- org.example:indirect:1.0 -> 2.0
\--- org.jetbrains.kotlin:kotlin-gradle-plugin:2.3.21

> Task :app:buildEnvironment

No dependencies

BUILD SUCCESSFUL in 5s
"""


class PluginGraphTests(unittest.TestCase):
    def test_selected_root_graph_is_partial_not_release(self):
        result = mod.audit(FIXTURE.encode())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["moduleCounts"], {"root": 3, "app": 0})
        self.assertFalse(result["releaseApproved"])
        self.assertFalse(result["artifactHashesCovered"])
        self.assertEqual(result["inventoryCompleteness"], "PARTIAL")

    def test_missing_kotlin_plugin_blocks(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(FIXTURE.replace("kotlin-gradle-plugin:2.3.21", "kotlin-gradle-plugin:2.3.20").encode())

    def test_missing_android_plugin_blocks(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(FIXTURE.replace("com.android.tools.build:gradle:8.13.2", "com.android.tools.build:gradle:8.13.1").encode())

    def test_failed_dependency_blocks_before_parse(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(FIXTURE.replace("org.example:indirect:1.0 -> 2.0", "org.example:indirect:1.0 FAILED").encode())

    def test_strict_constraint_selected_version_is_resolved(self):
        actual = FIXTURE.replace(
            "org.example:indirect:1.0 -> 2.0",
            "org.example:indirect:{strictly 2.0.21} -> 2.0.21 (c)")
        result = mod.audit(actual.encode())
        self.assertIn(
            "pkg:maven/org.example/indirect@2.0.21",
            [x["purl"] for x in result["root"]]
        )

    def test_unresolved_strict_constraint_is_blocked(self):
        actual = FIXTURE.replace(
            "org.example:indirect:1.0 -> 2.0",
            "org.example:indirect:{strictly 2.0.21}")
        with self.assertRaises(mod.AuditError):
            mod.audit(actual.encode())

    def test_invalid_selected_version_blocks(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(FIXTURE.replace("indirect:1.0 -> 2.0", "indirect:1.0 -> 2.+").encode())

    def test_missing_app_task_blocks(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(FIXTURE.replace("> Task :app:buildEnvironment", "> Task :app:help").encode())

    def test_failed_gradle_run_blocks(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(FIXTURE.replace("BUILD SUCCESSFUL", "BUILD FAILED").encode())

    def test_conflicting_resolved_transitive_versions_block(self):
        with self.assertRaises(mod.AuditError):
            mod.audit(FIXTURE.replace("No dependencies", "+--- org.example:indirect:9.0\nNo dependencies").replace(
                "indirect:1.0 -> 2.0", "indirect:1.0 -> 2.0\n+--- org.example:indirect:3.0").encode())


if __name__ == "__main__":
    unittest.main()
