"""Offline synthetic negative and green tests for two exact gradle813 JARs."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "audit_gradle813_classifier_jars.py"
spec = importlib.util.spec_from_file_location("gradle813_classifier", PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
REAL_TARGETS = dict(mod.TARGETS)
BYTES = b"synthetic-fixture: not authentic JetBrains classifier bytecode"
FAKE_SHA = hashlib.sha256(BYTES).hexdigest()


def fixture():
    modules = []
    for purl, (filename, _) in sorted(mod.TARGETS.items()):
        modules.append({
            "purl": purl, "cachedFiles": [{
                "filename": filename, "sha256": FAKE_SHA, "byteSize": len(BYTES),
                "classifier": "gradle813", "binaryOrigin": "NOT_VERIFIED",
                "sourceVerification": "LOCAL_BYTES_ONLY",
            }],
        })
    return {
        "status": "PASS_WITH_GAPS", "inventoryCompleteness": "PARTIAL",
        "licenseApproval": "NOT_VERIFIED", "originVerified": False,
        "releaseApproved": False, "sbomComplete": False,
        "counts": {"modules": len(modules)}, "modules": modules,
    }


class ClassifierMavenParityTests(unittest.TestCase):
    def setUp(self):
        # Synthetic bytes can never satisfy production hardcoded SHA pins.
        self.assertEqual(len(REAL_TARGETS), 2)
        self.patcher = patch.dict(
            mod.TARGETS,
            {purl: (filename, FAKE_SHA)
             for purl, (filename, _) in REAL_TARGETS.items()},
            clear=True,
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_real_production_digest_allowlist_remains_fixed(self):
        self.assertEqual(REAL_TARGETS, {
            "pkg:maven/org.jetbrains.kotlin/fus-statistics-gradle-plugin@2.3.21": (
                "fus-statistics-gradle-plugin-2.3.21-gradle813.jar",
                "73379b384d9da66419b5f4d5c83de1a99dd7f195662bc45c39443859e63e18b2",
            ),
            "pkg:maven/org.jetbrains.kotlin/kotlin-gradle-plugin-api@2.3.21": (
                "kotlin-gradle-plugin-api-2.3.21-gradle813.jar",
                "ad58d2638ee041f6ce4e73e9782ebf528e18cf9003b1099aa7045ec958e3c195",
            ),
        })

    def test_green_official_bytes_without_publisher_or_license_approval(self):
        seen = []
        result = mod.audit(fixture(), fetcher=lambda url: seen.append(url) or BYTES)
        self.assertEqual(result["status"], "SOURCE_BYTE_PARITY_PASS")
        self.assertEqual(result["sourceByteMatches"], 2)
        self.assertEqual(result["notSourceVerified"], 0)
        self.assertEqual(len(set(seen)), 2)
        self.assertTrue(all(x.startswith(mod.ORIGIN + "/") and x.endswith("-gradle813.jar")
                            for x in seen))
        for flag in ("publisherSignatureVerified", "originAttributionVerified",
                     "parentLicenseInheritanceVerified", "sbomComplete", "releaseApproved"):
            self.assertFalse(result[flag])
        self.assertEqual(result["licenseClosure"], "NOT_VERIFIED")
        self.assertEqual(result["noticeClosure"], "NOT_VERIFIED")
        self.assertTrue(all(not row["licenseApproved"] for row in result["records"]))

    def test_changed_upstream_byte_fails_closed(self):
        with self.assertRaisesRegex(mod.AuditError, "OFFICIAL_CLASSIFIER_BYTE_MISMATCH"):
            mod.audit(fixture(), fetcher=lambda _: BYTES + b"t")

    def test_changed_local_sha_cannot_be_accepted_even_if_upstream_matches(self):
        evidence = fixture()
        evidence["modules"][0]["cachedFiles"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(mod.AuditError, "PINNED_CLASSIFIER_LOCAL_SHA_MISMATCH"):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_wrong_size_fails_closed(self):
        evidence = fixture()
        evidence["modules"][0]["cachedFiles"][0]["byteSize"] += 1
        with self.assertRaisesRegex(mod.AuditError, "OFFICIAL_CLASSIFIER_BYTE_MISMATCH"):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_over_limit_byte_count_is_rejected(self):
        evidence = fixture()
        evidence["modules"][0]["cachedFiles"][0]["byteSize"] = mod.MAX_JAR + 1
        with self.assertRaises(mod.AuditError):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_classifier_downgrade_is_rejected(self):
        evidence = fixture()
        evidence["modules"][0]["cachedFiles"][0]["classifier"] = None
        with self.assertRaises(mod.AuditError):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_forged_local_provenance_is_rejected(self):
        evidence = fixture()
        evidence["modules"][0]["cachedFiles"][0]["binaryOrigin"] = "PUBLISHER_SIGNED"
        with self.assertRaises(mod.AuditError):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_direct_license_claim_must_not_elevate_inventory(self):
        evidence = fixture()
        evidence["licenseApproval"] = "APPROVED"
        with self.assertRaises(mod.AuditError):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_release_approval_forgery_is_rejected(self):
        evidence = fixture()
        evidence["releaseApproved"] = True
        with self.assertRaises(mod.AuditError):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_duplicate_classifier_sha_evidence_is_rejected(self):
        evidence = fixture()
        file = evidence["modules"][0]["cachedFiles"][0]
        evidence["modules"][0]["cachedFiles"].append(dict(file))
        with self.assertRaisesRegex(mod.AuditError, "ambiguous"):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_duplicate_module_identity_is_rejected(self):
        evidence = fixture()
        evidence["modules"].append(dict(evidence["modules"][0]))
        evidence["counts"]["modules"] += 1
        with self.assertRaisesRegex(mod.AuditError, "duplicated"):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_extra_module_not_downloaded(self):
        evidence = fixture()
        evidence["modules"].append({"purl": "pkg:maven/org.other/other@1.0",
                                    "cachedFiles": []})
        evidence["counts"]["modules"] += 1
        seen = []
        mod.audit(evidence, fetcher=lambda url: seen.append(url) or BYTES)
        self.assertEqual(len(seen), 2)

    def test_missing_local_classifier_is_unverified(self):
        evidence = fixture()
        evidence["modules"][0]["cachedFiles"] = []
        report = mod.audit(evidence, fetcher=lambda _: BYTES)
        self.assertEqual(report["status"], "BLOCKED_SOURCE_NOT_VERIFIED")
        self.assertEqual(report["sourceByteMatches"], 1)
        self.assertEqual(report["notSourceVerified"], 1)
        self.assertEqual(report["records"][0]["status"], "LOCAL_CLASSIFIER_JAR_NOT_CACHED")

    def test_upstream_404_is_unverified(self):
        report = mod.audit(fixture(), fetcher=lambda _: None)
        self.assertEqual(report["notSourceVerified"], 2)
        self.assertTrue(all(row["status"] == "OFFICIAL_JAR_NOT_FOUND"
                            for row in report["records"]))

    def test_transport_failure_does_not_become_pass(self):
        def unavailable(_):
            raise mod.AuditError("official Maven Central transport unavailable")
        report = mod.audit(fixture(), fetcher=unavailable)
        self.assertEqual(report["status"], "BLOCKED_SOURCE_NOT_VERIFIED")
        self.assertTrue(all(row["status"] == "REMOTE_NOT_VERIFIED"
                            for row in report["records"]))

    def test_redirect_is_fail_closed_not_fallback(self):
        def redirect(_):
            raise mod.AuditError("Maven Central redirect is forbidden")
        with self.assertRaisesRegex(mod.AuditError, "redirect"):
            mod.audit(fixture(), fetcher=redirect)

    def test_arbitrary_source_url_is_refused(self):
        with self.assertRaisesRegex(mod.AuditError, "non-allowlisted"):
            mod.retrieve("https://maven.example.org/org/jetbrains/kotlin/other.jar")

    def test_missing_coordinate_is_rejected(self):
        evidence = fixture()
        evidence["modules"][0]["purl"] = "pkg:maven/org.fake/fake@2.3.21"
        with self.assertRaisesRegex(mod.AuditError, "missing required"):
            mod.audit(evidence, fetcher=lambda _: BYTES)

    def test_wrong_filename_does_not_generate_fake_match(self):
        evidence = fixture()
        evidence["modules"][0]["cachedFiles"][0]["filename"] += ".bak"
        report = mod.audit(evidence, fetcher=lambda _: BYTES)
        self.assertEqual(report["notSourceVerified"], 1)

    def test_input_missing_is_cli_blocked(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(mod.main(["--plugin-inventory", str(root / "missing.json"),
                                       "--output", str(root / "out.json")]), 2)

    def test_cli_offline_404_writes_blocked_report(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "in.json").write_text(json.dumps(fixture()), encoding="utf-8")
            with patch.object(mod, "retrieve", return_value=None):
                code = mod.main(["--plugin-inventory", str(root / "in.json"),
                                 "--output", str(root / "out.json")])
            self.assertEqual(code, 2)
            report = json.loads((root / "out.json").read_text(encoding="utf-8"))
            self.assertFalse(report["releaseApproved"])
            self.assertEqual(report["status"], "BLOCKED_SOURCE_NOT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
