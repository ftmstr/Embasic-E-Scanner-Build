"""Offline bounded Maven build-tool JAR byte/provenance regression suite."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "audit_gradle_central_binary_batch.py"
spec = importlib.util.spec_from_file_location("gradle_central_batch", PATH)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
BYTES = b"synthetic cache JAR for CI negative tests, never a real product binary"


def sample():
    modules = []
    for purl in audit.TARGETS:
        _, name = purl.split("pkg:maven/", 1)
        group, variant = name.split("/", 1)
        artifact, version = variant.rsplit("@", 1)
        modules.append({
            "purl": purl, "licenseMetadataState": "POM_WITHOUT_DIRECT_LICENSE_NAME",
            "cachedFiles": [{
                "filename": artifact + "-" + version + ".jar",
                "sha256": hashlib.sha256(BYTES).hexdigest(),
                "byteSize": len(BYTES),
                "sourceVerification": "LOCAL_BYTES_ONLY",
            }],
        })
    return {
        "status": "PASS_WITH_GAPS", "inventoryCompleteness": "PARTIAL",
        "licenseApproval": "NOT_VERIFIED", "originVerified": False,
        "releaseApproved": False, "sbomComplete": False,
        "counts": {"modules": len(modules)}, "modules": modules,
    }


class GradleCentralBinaryBatchTests(unittest.TestCase):
    def test_four_fixed_maven_coordinates_match_but_no_signing_claim(self):
        seen = []
        def fake(url):
            seen.append(url)
            return BYTES
        result = audit.audit(sample(), fetcher=fake)
        self.assertEqual(result["sourceByteMatches"], 4)
        self.assertEqual(result["status"], "SOURCE_BYTE_PARITY_PASS")
        self.assertFalse(result["publisherSignatureVerified"])
        self.assertFalse(result["originAttributionVerified"])
        self.assertFalse(result["releaseApproved"])
        self.assertEqual(len(seen), 4)
        self.assertTrue(all(u.startswith(audit.ORIGIN + "/") for u in seen))

    def test_distinct_no_direct_pom_license_gap_coordinates_are_pinned(self):
        self.assertEqual(set(audit.TARGETS), {
            "pkg:maven/com.google.guava/failureaccess@1.0.2",
            "pkg:maven/com.google.protobuf/protobuf-java-util@3.25.5",
            "pkg:maven/com.google.jimfs/jimfs@1.1",
            "pkg:maven/com.google.auto.value/auto-value-annotations@1.6.2",
        })
        self.assertEqual(len(set(audit.TARGETS)), 4)
        result = audit.audit(sample(), fetcher=lambda _: BYTES)
        self.assertTrue(all(
            item["directPomLicenseMetadata"] == "POM_WITHOUT_DIRECT_LICENSE_NAME"
            and item["licenseApproved"] is False
            for item in result["records"]))

    def test_switch_to_direct_license_metadata_must_reassess_selection(self):
        changed = sample()
        changed["modules"][0]["licenseMetadataState"] = "DIRECT_POM_LICENSE_NAME"
        with self.assertRaisesRegex(audit.AuditError, "expected child-POM"):
            audit.audit(changed, fetcher=lambda _: BYTES)

    def test_mismatch_is_a_fail_closed_exception(self):
        with self.assertRaisesRegex(audit.AuditError, "OFFICIAL_BINARY_MISMATCH"):
            audit.audit(sample(), fetcher=lambda _: b"tampered JAR")

    def test_not_found_keeps_an_evidence_gap(self):
        result = audit.audit(sample(), fetcher=lambda _: None)
        self.assertEqual(result["notSourceVerified"], 4)
        self.assertEqual(result["status"], "PARTIAL_EVIDENCE_ONLY")
        self.assertTrue(all(x["status"] == "OFFICIAL_ARTIFACT_NOT_FOUND"
                            for x in result["records"]))

    def test_transport_failure_does_not_claim_pass(self):
        def network_down(url):
            raise audit.AuditError("official source transport unavailable")
        result = audit.audit(sample(), fetcher=network_down)
        self.assertEqual(result["sourceByteMatches"], 0)
        self.assertTrue(all(x["status"] == "REMOTE_NOT_VERIFIED"
                            for x in result["records"]))

    def test_missing_local_jar_is_explicit(self):
        raw = sample()
        raw["modules"][0]["cachedFiles"] = []
        result = audit.audit(raw, fetcher=lambda _: BYTES)
        self.assertEqual(result["sourceByteMatches"], 3)
        self.assertEqual(result["records"][0]["status"], "LOCAL_STANDARD_JAR_NOT_CACHED")

    def test_unknown_classifier_not_guessed(self):
        raw = sample()
        target = raw["modules"][0]["cachedFiles"][0]
        target["filename"] = target["filename"][:-4] + "-custom.jar"
        result = audit.audit(raw, fetcher=lambda _: BYTES)
        self.assertEqual(result["notSourceVerified"], 1)
        self.assertEqual(result["records"][0]["unreviewedJarVariants"], [target["filename"]])

    def test_duplicate_cached_jar_rejected(self):
        raw = sample()
        raw["modules"][0]["cachedFiles"].append(dict(raw["modules"][0]["cachedFiles"][0]))
        with self.assertRaisesRegex(audit.AuditError, "ambiguous"):
            audit.audit(raw, fetcher=lambda _: BYTES)

    def test_missing_required_coordinate_rejected(self):
        raw = sample()
        raw["modules"][0]["purl"] = "pkg:maven/org.example/other@0.9"
        with self.assertRaisesRegex(audit.AuditError, "mandatory"):
            audit.audit(raw, fetcher=lambda _: BYTES)

    def test_forged_release_or_license_approval_rejected(self):
        raw = sample()
        raw["releaseApproved"] = True
        with self.assertRaises(audit.AuditError):
            audit.audit(raw, fetcher=lambda _: BYTES)
        raw["releaseApproved"] = False
        raw["licenseApproval"] = "APPROVED"
        with self.assertRaises(audit.AuditError):
            audit.audit(raw, fetcher=lambda _: BYTES)

    def test_missing_or_invalid_sha_rejected(self):
        raw = sample()
        raw["modules"][0]["cachedFiles"][0]["sha256"] = "no"
        with self.assertRaises(audit.AuditError):
            audit.audit(raw, fetcher=lambda _: BYTES)

    def test_wrong_declared_byte_size_fails_closed(self):
        raw = sample()
        raw["modules"][0]["cachedFiles"][0]["byteSize"] += 1
        with self.assertRaisesRegex(audit.AuditError, "OFFICIAL_BINARY_MISMATCH"):
            audit.audit(raw, fetcher=lambda _: BYTES)

    def test_oversized_cached_evidence_rejected(self):
        raw = sample()
        raw["modules"][0]["cachedFiles"][0]["byteSize"] = audit.MAX_JAR + 1
        with self.assertRaises(audit.AuditError):
            audit.audit(raw, fetcher=lambda _: BYTES)

    def test_direct_untrusted_license_claim_stays_unapproved(self):
        result = audit.audit(sample(), fetcher=lambda _: BYTES)
        self.assertEqual(result["licenseClosure"], "NOT_VERIFIED")
        self.assertEqual(result["noticeClosure"], "NOT_VERIFIED")
        self.assertFalse(result["sbomComplete"])
        self.assertTrue(all(x["licenseApproved"] is False for x in result["records"]))

    def test_invalid_manual_repository_origin_is_refused(self):
        with self.assertRaisesRegex(audit.AuditError, "not allowlisted"):
            audit.retrieve("https://example.invalid/guava.jar")

    def test_missing_input_path_fails_in_cli(self):
        with TemporaryDirectory() as directory:
            p = Path(directory)
            self.assertEqual(audit.main(["--plugin-inventory", str(p / "missing.json"),
                                         "--output", str(p / "out.json")]), 2)


if __name__ == "__main__":
    unittest.main()
