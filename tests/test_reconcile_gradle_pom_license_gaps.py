"""Synthetic-only negative tests: selected Maven POM legal review queues never approve releases."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "reconcile_gradle_pom_license_gaps.py"
spec = importlib.util.spec_from_file_location("pom_legal_queue", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

CHILD = "pkg:maven/com.example/no-pom@1.0.0"
NO_LIC = "pkg:maven/com.example/no-lic@1.2.0"
PARENT = "pkg:maven/com.example/parent@1.0"


def fixture():
    source_url = ("https://repo.maven.apache.org/maven2/"
                  "com/example/no-pom/1.0.0/no-pom-1.0.0.pom")
    modules = [
        {"purl": CHILD, "licenseMetadataState": "POM_NOT_CACHED",
         "pomDeclaredLicenses": [], "unresolvedPomParents": [],
         "parentPomEvidence": [], "scopes": ["root"]},
        {"purl": NO_LIC, "licenseMetadataState": "POM_WITHOUT_DIRECT_LICENSE_NAME",
         "pomDeclaredLicenses": [],
         "unresolvedPomParents": ["com.example:parent:1.0"],
         "parentPomEvidence": [[{"coordinate": "com.example:parent:1.0",
                                "status": "PARENT_POM_NOT_CACHED",
                                "sha256": None, "unverifiedLicenseNames": [],
                                "licenseApproved": False}]],
         "scopes": ["root", "app"]},
        {"purl": "pkg:maven/com.example/ok@2.0.0",
         "licenseMetadataState": "DIRECT_POM_LICENSE_NAME",
         "pomDeclaredLicenses": [{"name": "Apache-2.0", "url": "https://example.org",
                                  "evidence": "UNVERIFIED_SUPPLIER_POM"}],
         "unresolvedPomParents": [], "parentPomEvidence": [], "scopes": ["app"]},
    ]
    inventory = {
        "schemaVersion": 1, "scope": "Android Gradle root/app buildEnvironment LOCAL cache evidence only",
        "status": "PASS_WITH_GAPS", "partialNoticeCheck": "PASS",
        "originVerified": False, "parentLicenseInheritanceVerified": False,
        "licenseApproval": "NOT_VERIFIED", "inventoryCompleteness": "PARTIAL",
        "noticeClosure": "NOT_VERIFIED", "sbomComplete": False,
        "releaseApproved": False, "modules": modules,
        "counts": {"modules": 3, "pomWithLicenseNames": 1,
                   "pomNotCached": 1, "pomWithoutDirectLicenseName": 1,
                   "unreadablePom": 0},
        "missingDirectLicenseEvidence": [
            {"purl": CHILD, "reason": "POM_NOT_CACHED",
             "unresolvedPomParents": []},
            {"purl": NO_LIC, "reason": "POM_WITHOUT_DIRECT_LICENSE_NAME",
             "unresolvedPomParents": ["com.example:parent:1.0"]}
        ],
    }
    research = {
        "schemaVersion": 1, "scope": "PUBLIC-Gradle-selected-missing-POM-and-parent-only",
        "status": "PARTIAL_EVIDENCE_ONLY", "originVerified": False,
        "artifactBinaryVerified": False, "parentLicenseInheritanceVerified": False,
        "licenseClosure": "NOT_VERIFIED", "sbomComplete": False,
        "releaseApproved": False, "originalDirectLicenseGaps": 2,
        "targets": 2, "remotePomMetadataRetrieved": 1, "stillUnretrieved": 1,
        "records": [
            {"purl": CHILD, "reasons": ["SELECTED_POM_NOT_CACHED"],
             "status": "UPSTREAM_POM_METADATA_RETRIEVED",
             "sha256": "a" * 64, "byteSize": 123,
             "officialRepositoryUrl": source_url,
             "supplierDeclaredLicenses": [
                 {"name": "Apache License 2.0",
                  "url": "https://example.org",
                  "evidence": "UNVERIFIED_REMOTE_POM_DECLARATION"}],
             "unverifiedParent": None,
             "licenseApproved": False, "publisherSignatureVerified": False},
            {"purl": PARENT, "reasons": ["MISSING_PARENT_POM"],
             "status": "UPSTREAM_POM_UNAVAILABLE",
             "sha256": None, "byteSize": None,
             "officialRepositoryUrl": None,
             "supplierDeclaredLicenses": [], "unverifiedParent": None,
             "licenseApproved": False, "publisherSignatureVerified": False},
        ]
    }
    return inventory, research


class SelectedPomLegalQueueTests(unittest.TestCase):
    def test_good_evidence_still_has_all_legal_gaps(self):
        plugin, research = fixture()
        r = mod.audit(plugin, research)
        self.assertEqual(r["counts"]["directPOMLicenseGaps"], 2)
        self.assertEqual(r["counts"]["remoteMetadataRetrieved"], 1)
        self.assertEqual([x["purl"] for x in r["reviewQueue"]], [NO_LIC, CHILD])
        self.assertEqual(r["status"], "REVIEW_QUEUE_ONLY_LEGAL_NO_GO")
        self.assertTrue(r["allChildGapsRemainUnresolved"])
        self.assertEqual(r["microsoftSDKBuildToolsExactRedistRights"],
                         "NOT_VERIFIED_SEPARATE_GATE")
        self.assertEqual(r["licenseClosure"], "NOT_VERIFIED")
        self.assertFalse(r["releaseApproved"])
        self.assertFalse(r["sbomComplete"])
        for x in r["reviewQueue"]:
            self.assertFalse(x["licenseApproved"])
            self.assertFalse(x["redistributionRightsVerified"])
        child = next(x for x in r["reviewQueue"] if x["purl"] == CHILD)
        self.assertEqual(child["remoteChildDeclaredLicenseNames"],
                         ["Apache License 2.0"])

    def test_no_child_pom_research_stays_unresolved(self):
        plugin, research = fixture()
        row = research["records"][0]
        row.update({"status": "UPSTREAM_POM_UNAVAILABLE", "sha256": None,
                    "byteSize": None, "officialRepositoryUrl": None,
                    "supplierDeclaredLicenses": []})
        research["remotePomMetadataRetrieved"] = 0
        research["stillUnretrieved"] = 2
        result = mod.audit(plugin, research)
        child = next(x for x in result["reviewQueue"] if x["purl"] == CHILD)
        self.assertEqual(child["nextAction"], "OBTAIN_EXACT_CHILD_POM_AND_LICENSE_TEXT")

    def test_plugin_approval_flag_is_rejected(self):
        plugin, research = fixture()
        plugin["releaseApproved"] = True
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_plugin_parent_inheritance_spoof_is_rejected(self):
        plugin, research = fixture()
        plugin["parentLicenseInheritanceVerified"] = True
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_remote_research_release_escalation_rejected(self):
        plugin, research = fixture()
        research["releaseApproved"] = True
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_remote_research_signed_provenance_spoof_rejected(self):
        plugin, research = fixture()
        research["originVerified"] = True
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_renamed_selected_module_rejected(self):
        plugin, research = fixture()
        plugin["modules"][0]["purl"] = CHILD + "../fake"
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_duplicate_module_rejected(self):
        plugin, research = fixture()
        plugin["modules"][1]["purl"] = plugin["modules"][0]["purl"]
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_deleted_gap_refused(self):
        plugin, research = fixture()
        plugin["missingDirectLicenseEvidence"].pop()
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_count_spoof_is_rejected(self):
        plugin, research = fixture()
        plugin["counts"]["pomNotCached"] = 0
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_claimed_license_on_missing_child_is_rejected(self):
        plugin, research = fixture()
        plugin["modules"][0]["pomDeclaredLicenses"] = [
            {"name": "MIT", "evidence": "UNVERIFIED_SUPPLIER_POM"}]
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_elevated_parent_claim_rejected(self):
        plugin, research = fixture()
        plugin["modules"][1]["parentPomEvidence"][0][0]["licenseApproved"] = True
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_parent_metadata_forgery_rejected(self):
        plugin, research = fixture()
        plugin["modules"][1]["parentPomEvidence"][0][0]["status"] = "LICENSE_VERIFIED"
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_renamed_parent_pom_source_rejected(self):
        plugin, research = fixture()
        research["records"][1]["purl"] = "pkg:maven/com.example/evil@1.0"
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_duplicate_source_row_rejected(self):
        plugin, research = fixture()
        research["records"][1] = copy.deepcopy(research["records"][0])
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_wrong_source_host_rejected(self):
        plugin, research = fixture()
        research["records"][0]["officialRepositoryUrl"] = \
            "https://example.com/repo/no-pom-1.0.0.pom"
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_wrong_source_version_rejected(self):
        plugin, research = fixture()
        research["records"][0]["officialRepositoryUrl"] = \
            research["records"][0]["officialRepositoryUrl"].replace("/1.0.0/", "/1.0.1/")
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_missing_source_sha_rejected(self):
        plugin, research = fixture()
        research["records"][0]["sha256"] = None
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_upstream_approval_claim_rejected(self):
        plugin, research = fixture()
        research["records"][0]["licenseApproved"] = True
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_remote_licence_elevation_rejected(self):
        plugin, research = fixture()
        research["records"][0]["supplierDeclaredLicenses"][0]["licenseApproved"] = True
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_source_metadata_without_bytes_rejected(self):
        plugin, research = fixture()
        research["records"][1]["supplierDeclaredLicenses"] = [
            {"name": "MIT", "evidence": "UNVERIFIED_REMOTE_POM_DECLARATION"}]
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_wrong_source_retrieval_totals_rejected(self):
        plugin, research = fixture()
        research["remotePomMetadataRetrieved"] += 1
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_missing_parent_gap_hint_rejected(self):
        plugin, research = fixture()
        plugin["missingDirectLicenseEvidence"][1]["unresolvedPomParents"] = []
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_traversal_in_parent_coordinate_rejected(self):
        plugin, research = fixture()
        plugin["modules"][1]["parentPomEvidence"][0][0]["coordinate"] = "com.example:..:1.0"
        with self.assertRaises(mod.AuditError):
            mod.audit(plugin, research)

    def test_invalid_local_files_fail_closed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual(mod.main(["--plugin-report", str(root/"missing.json"),
                                       "--pom-research", str(root/"no.json"),
                                       "--output", str(root/"result.json")]), 2)

    def test_cli_writes_legal_queue_but_not_approval(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            plugin, research = fixture()
            (root/"plugin.json").write_text(json.dumps(plugin))
            (root/"research.json").write_text(json.dumps(research))
            self.assertEqual(mod.main(["--plugin-report", str(root/"plugin.json"),
                                       "--pom-research", str(root/"research.json"),
                                       "--output", str(root/"result.json")]), 0)
            result = json.loads((root/"result.json").read_text())
            self.assertEqual(len(result["reviewQueue"]), 2)
            self.assertFalse(result["releaseApproved"])


if __name__ == "__main__":
    unittest.main()
