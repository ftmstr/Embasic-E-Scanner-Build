"""Synthetic offline license/provenance boundary tests for missing Maven POMs."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SRC = Path(__file__).resolve().parents[1] / "scripts" / "audit_missing_maven_pom_sources.py"
spec = importlib.util.spec_from_file_location("pom_remote", SRC)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
CHILD = "pkg:maven/org.example/widget@1.0"
PARENT = "pkg:maven/org.example/parent@2.0"
POM = (b'<project xmlns="http://maven.apache.org/POM/4.0.0">'
       b'<groupId>org.example</groupId><artifactId>widget</artifactId>'
       b'<version>1.0</version><licenses><license><name>MIT</name></license>'
       b'</licenses></project>')


def fixture():
    return {
        "status": "PASS_WITH_GAPS", "releaseApproved": False,
        "originVerified": False, "parentLicenseInheritanceVerified": False,
        "inventoryCompleteness": "PARTIAL", "licenseApproval": "NOT_VERIFIED",
        "modules": [{
            "purl": CHILD, "licenseMetadataState": "POM_NOT_CACHED",
            "parentPomEvidence": [[
                {"coordinate": "org.example:parent:2.0",
                 "status": "PARENT_POM_NOT_CACHED"}]],
        }],
        "missingDirectLicenseEvidence": [
            {"purl": CHILD, "reason": "POM_NOT_CACHED"}
        ],
    }


class MavenPomSourceResearchTests(unittest.TestCase):
    def test_exact_selected_and_missing_parent_target_set(self):
        targets = mod.targets_from_report(fixture())
        self.assertEqual([x["purl"] for x in targets], [PARENT, CHILD])
        self.assertEqual(targets[0]["reasons"], ["MISSING_PARENT_POM"])

    def test_bounded_official_pom_sha_does_not_grant_license(self):
        visited = []
        def fake(url):
            visited.append(url)
            return POM if "/widget/1.0/" in url else None
        report = mod.audit(fixture(), fetch=fake)
        self.assertEqual(report["targets"], 2)
        self.assertEqual(report["remotePomMetadataRetrieved"], 1)
        self.assertEqual(report["stillUnretrieved"], 1)
        self.assertEqual(report["originalDirectLicenseGaps"], 1)
        self.assertFalse(report["originVerified"])
        self.assertFalse(report["artifactBinaryVerified"])
        self.assertFalse(report["releaseApproved"])
        widget = next(x for x in report["records"] if x["purl"] == CHILD)
        self.assertEqual(widget["sha256"], hashlib.sha256(POM).hexdigest())
        self.assertEqual(widget["supplierDeclaredLicenses"][0]["name"], "MIT")
        self.assertFalse(widget["licenseApproved"])
        self.assertTrue(widget["officialRepositoryUrl"].startswith("https://repo.maven.apache.org/"))
        self.assertTrue(all(x.startswith(mod.HOSTS) for x in visited))

    def test_double_not_found_is_explicit_gap(self):
        report = mod.audit(fixture(), fetch=lambda url: None)
        self.assertEqual(report["remotePomMetadataRetrieved"], 0)
        self.assertEqual(report["stillUnretrieved"], 2)
        self.assertTrue(all(x["status"] == "UPSTREAM_POM_UNAVAILABLE" for x in report["records"]))

    def test_external_failure_is_not_success(self):
        def denied(url):
            raise mod.AuditError("remote POM transport unavailable")
        report = mod.audit(fixture(), fetch=denied)
        self.assertEqual(report["stillUnretrieved"], 2)
        self.assertTrue(all(all(z["status"] == "NOT_VERIFIED" for z in x["attempts"])
                            for x in report["records"]))

    def test_remote_pom_wrong_artifact_identity_rejected(self):
        wrong = POM.replace(b"<artifactId>widget</artifactId>", b"<artifactId>other</artifactId>")
        def fake(url):
            return wrong if "/widget/1.0/" in url else None
        with self.assertRaises(mod.AuditError):
            mod.audit(fixture(), fetch=fake)

    def test_doctype_xml_is_rejected(self):
        unsafe = b'<!DOCTYPE project [<!ENTITY x SYSTEM "file:///etc/passwd">]><project/>'
        with self.assertRaises(mod.AuditError):
            mod._pom_info(unsafe, "org.example", "widget", "1.0")

    def test_unexpected_license_approval_input_rejected(self):
        data = fixture()
        data["releaseApproved"] = True
        with self.assertRaises(mod.AuditError):
            mod.targets_from_report(data)

    def test_traversal_parent_coordinate_rejected(self):
        data = fixture()
        data["modules"][0]["parentPomEvidence"][0][0]["coordinate"] = "org.example:..:2.0"
        with self.assertRaises(mod.AuditError):
            mod.targets_from_report(data)

    def test_large_input_rejected(self):
        with TemporaryDirectory() as d:
            source = Path(d) / "graph.json"
            source.write_bytes(b" " * (mod.MAX_JSON_BYTES + 1))
            self.assertNotEqual(mod.main(["--plugin-report", str(source),
                                          "--output", str(Path(d) / "out.json")]), 0)

    def test_parent_license_not_automatically_assigned_to_child(self):
        child_no_license = (b'<project><groupId>org.example</groupId>'
                            b'<artifactId>widget</artifactId><version>1.0</version>'
                            b'<parent><groupId>org.example</groupId>'
                            b'<artifactId>parent</artifactId><version>2.0</version></parent>'
                            b'</project>')
        def fake(url):
            return child_no_license if "/widget/1.0/" in url else None
        result = mod.audit(fixture(), fetch=fake)
        widget = next(x for x in result["records"] if x["purl"] == CHILD)
        self.assertEqual(widget["supplierDeclaredLicenses"], [])
        self.assertEqual(widget["unverifiedParent"], "org.example:parent:2.0")
        self.assertFalse(result["parentLicenseInheritanceVerified"])


if __name__ == "__main__":
    unittest.main()
