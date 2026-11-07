"""Closed-world plugin JAR source-byte regression tests (no real network)."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "audit_pinned_gradle_plugin_jars.py"
spec = importlib.util.spec_from_file_location("pinned_gradle", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
BINARY = b"synthetic plugin jar bytes, NOT actual Gradle/Kotlin bytecode"


def fixture():
    modules = []
    for purl in sorted(mod.EXPECTED):
        _, tail = purl.split("/", 1)
        group, suffix = tail.split("/", 1)
        artifact, version = suffix.split("@", 1)
        modules.append({
            "purl": purl,
            "cachedFiles": [{
                "filename": f"{artifact}-{version}.jar",
                "sha256": hashlib.sha256(BINARY).hexdigest(),
                "byteSize": len(BINARY),
                "sourceVerification": "LOCAL_BYTES_ONLY",
            }]
        })
    return {
        "status": "PASS_WITH_GAPS", "inventoryCompleteness": "PARTIAL",
        "licenseApproval": "NOT_VERIFIED", "originVerified": False,
        "releaseApproved": False, "sbomComplete": False,
        "modules": modules,
    }


class PinnedGradlePluginTests(unittest.TestCase):
    def test_exact_two_official_bytes_matched_without_approval(self):
        calls = []
        def source(url):
            calls.append(url)
            return BINARY
        result = mod.audit(fixture(), fetcher=source)
        self.assertEqual(result["status"], "SOURCE_BYTE_PARITY_PASS")
        self.assertEqual(result["sourceByteMatches"], 2)
        self.assertFalse(result["publisherSignatureVerified"])
        self.assertFalse(result["releaseApproved"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(set(calls)), 2)
        self.assertTrue(any("dl.google.com" in x for x in calls))
        self.assertTrue(any("repo.maven.apache.org" in x for x in calls))

    def test_source_byte_mismatch_is_fail_closed(self):
        with self.assertRaisesRegex(mod.AuditError, "BYTE_MISMATCH"):
            mod.audit(fixture(), fetcher=lambda url: b"mismatched binary")

    def test_missing_upstream_binary_is_explicit_gap(self):
        result = mod.audit(fixture(), fetcher=lambda url: None)
        self.assertEqual(result["status"], "PARTIAL_EVIDENCE_ONLY")
        self.assertEqual(result["unverifiedPinnedPluginJars"], 2)
        self.assertTrue(all(x["status"] == "OFFICIAL_BINARY_NOT_FOUND"
                            for x in result["records"]))

    def test_missing_local_jar_is_not_verified(self):
        value = fixture()
        value["modules"][0]["cachedFiles"] = []
        result = mod.audit(value, fetcher=lambda url: BINARY)
        self.assertEqual(result["status"], "PARTIAL_EVIDENCE_ONLY")
        self.assertEqual(result["sourceByteMatches"], 1)
        self.assertEqual(result["records"][0]["status"], "LOCAL_JAR_NOT_PRESENT")

    def test_transport_failure_is_not_verified(self):
        def down(url):
            raise mod.AuditError("upstream network unavailable")
        result = mod.audit(fixture(), fetcher=down)
        self.assertTrue(all(x["status"] == "REMOTE_NOT_VERIFIED"
                            for x in result["records"]))
        self.assertFalse(result["originAttributionVerified"])

    def test_extra_module_cannot_become_target(self):
        value = fixture()
        value["modules"].append({"purl": "pkg:maven/org.other/third@1.0",
                                 "cachedFiles": []})
        seen = []
        result = mod.audit(value, fetcher=lambda url: seen.append(url) or BINARY)
        self.assertEqual(result["selectedPinnedPluginJarCount"], 2)
        self.assertEqual(len(seen), 2)

    def test_mandatory_plugin_missing_is_rejected(self):
        value = fixture()
        value["modules"][0]["purl"] = "pkg:maven/org.fake/fake@0.1"
        with self.assertRaises(mod.AuditError):
            mod.audit(value, fetcher=lambda url: BINARY)

    def test_forged_source_license_approval_rejected(self):
        value = fixture()
        value["licenseApproval"] = "PASS"
        with self.assertRaises(mod.AuditError):
            mod.audit(value, fetcher=lambda url: BINARY)

    def test_duplicate_plugin_record_rejected(self):
        value = fixture()
        value["modules"].append(value["modules"][0])
        with self.assertRaises(mod.AuditError):
            mod.audit(value, fetcher=lambda url: BINARY)

    def test_ambiguous_cached_plugin_jars_rejected(self):
        value = fixture()
        value["modules"][1]["cachedFiles"].append(dict(value["modules"][1]["cachedFiles"][0]))
        with self.assertRaises(mod.AuditError):
            mod.audit(value, fetcher=lambda url: BINARY)

    def test_bad_local_sha_rejected(self):
        value = fixture()
        value["modules"][0]["cachedFiles"][0]["sha256"] = "unsigned"
        with self.assertRaises(mod.AuditError):
            mod.audit(value, fetcher=lambda url: BINARY)

    def test_malformed_or_oversized_local_binary_rejected(self):
        value = fixture()
        value["modules"][0]["cachedFiles"][0]["byteSize"] = mod.MAX_JAR + 1
        with self.assertRaises(mod.AuditError):
            mod.audit(value, fetcher=lambda url: BINARY)

    def test_official_source_length_mismatch_fails(self):
        value = fixture()
        with self.assertRaises(mod.AuditError):
            mod.audit(value, fetcher=lambda url: BINARY + b"x")

    def test_cli_missing_inventory_is_blocked(self):
        with TemporaryDirectory() as d:
            code = mod.main(["--plugin-inventory", str(Path(d) / "missing.json"),
                             "--output", str(Path(d) / "result.json")])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
