"""Closed-world no-network tests for bounded Maven source-vs-cache byte parity."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

FILE = Path(__file__).resolve().parents[1] / "scripts" / "audit_maven_release_jar_bytes.py"
spec = importlib.util.spec_from_file_location("jar_upstream", FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
BLOB = b"synthetic JAR bytes only - not a publisher signing identity"
URL = "pkg:maven/org.example/test-library@1.2.3"


def inventory():
    return {
        "status": "PASS", "sourceVerification": "LOCAL_SHA256_ONLY",
        "transitiveLicenseClosure": "NOT_VERIFIED", "releaseApproved": False,
        "artifactCount": 1,
        "artifacts": [{"purl": URL, "sha256": hashlib.sha256(BLOB).hexdigest(),
                       "byteSize": len(BLOB), "licenseApproved": False,
                       "binaryProvenance": "NOT_VERIFIED"}],
    }


class MavenJarOfficialBytesTests(unittest.TestCase):
    def test_same_bytes_different_origin_claims_not_assumed(self):
        calls = []
        def source(url):
            calls.append(url)
            return BLOB
        report = m.audit(inventory(), fetch=source)
        self.assertEqual(report["status"], "SOURCE_BYTE_PARITY_PASS")
        self.assertEqual(report["sourceByteMatches"], 1)
        self.assertFalse(report["originAttributionVerified"])
        self.assertFalse(report["publisherSignatureVerified"])
        self.assertFalse(report["releaseApproved"])
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith("https://repo.maven.apache.org/maven2/"))

    def test_official_mismatch_is_fail_closed_not_mirror_fallback(self):
        calls = []
        def fake(url):
            calls.append(url)
            return b"altered source bytes"
        with self.assertRaisesRegex(m.AuditError, "BYTE_MISMATCH"):
            m.audit(inventory(), fetch=fake)
        self.assertEqual(len(calls), 1)

    def test_404_then_google_source_can_match(self):
        report = m.audit(inventory(), fetch=lambda url: None if "repo.maven.apache" in url else BLOB)
        self.assertEqual(report["sourceByteMatches"], 1)
        self.assertTrue(report["artifacts"][0]["sourceUrl"].startswith("https://dl.google.com/"))

    def test_both_missing_are_explicit_blocker(self):
        report = m.audit(inventory(), fetch=lambda url: None)
        self.assertEqual(report["status"], "BLOCKED_SOURCE_UNAVAILABLE")
        self.assertEqual(report["unverifiedSources"], 1)
        self.assertFalse(report["releaseApproved"])

    def test_transport_outage_cannot_claim_verification(self):
        def outage(url):
            raise m.AuditError("upstream JAR transport unavailable")
        report = m.audit(inventory(), fetch=outage)
        self.assertEqual(report["status"], "BLOCKED_SOURCE_UNAVAILABLE")
        self.assertEqual(len(report["artifacts"][0]["sourceAttempts"]), 2)

    def test_duplicate_module_identity_rejected(self):
        report = inventory()
        report["artifacts"].append(report["artifacts"][0])
        report["artifactCount"] = 2
        with self.assertRaises(m.AuditError):
            m.audit(report, fetch=lambda url: BLOB)

    def test_path_traversal_rejected(self):
        report = inventory()
        report["artifacts"][0]["purl"] = "pkg:maven/org.example/..@1.2.3"
        with self.assertRaises(m.AuditError):
            m.audit(report, fetch=lambda url: BLOB)

    def test_forged_release_approval_rejected(self):
        report = inventory()
        report["releaseApproved"] = True
        with self.assertRaises(m.AuditError):
            m.audit(report, fetch=lambda url: BLOB)

    def test_bogus_hash_rejected(self):
        report = inventory()
        report["artifacts"][0]["sha256"] = "not-sha"
        with self.assertRaises(m.AuditError):
            m.audit(report, fetch=lambda url: BLOB)

    def test_false_file_length_rejected(self):
        report = inventory()
        report["artifacts"][0]["byteSize"] = len(BLOB) + 1
        with self.assertRaises(m.AuditError):
            m.audit(report, fetch=lambda url: BLOB)

    def test_oversized_evidence_rejected(self):
        report = inventory()
        report["artifacts"][0]["byteSize"] = m.MAX_JAR + 1
        with self.assertRaises(m.AuditError):
            m.audit(report, fetch=lambda url: BLOB)

    def test_output_never_approves_licenses_or_sbom(self):
        r = m.audit(inventory(), fetch=lambda url: BLOB)
        self.assertFalse(r["sbomComplete"])
        self.assertEqual(r["licenseClosure"], "NOT_VERIFIED")
        self.assertTrue(all(a["licenseApproved"] is False for a in r["artifacts"]))

    def test_missing_input_inventory_rejected_in_cli(self):
        with TemporaryDirectory() as d:
            result = m.main(["--inventory", str(Path(d)/"missing.json"),
                             "--output", str(Path(d)/"report.json")])
            self.assertEqual(result, 2)


if __name__ == "__main__":
    unittest.main()
