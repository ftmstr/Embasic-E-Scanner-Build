"""Synthetic-only, rights-NOT-VERIFIED Jakarta Activation API 1.2.1 evidence tests."""
from __future__ import annotations

import copy
from io import BytesIO
import importlib.util
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location(
    "activation_api121_audit", SCRIPTS / "audit_activation_api121_exact_license.py")
auditlib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditlib)


def archive(license_text: bytes, notice_text: bytes, extra=()):
    out = BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(auditlib.ARCHIVE_LICENSE, license_text)
        z.writestr(auditlib.ARCHIVE_NOTICE, notice_text)
        for name, blob in extra:
            z.writestr(name, blob)
    return out.getvalue()


def fixture():
    child = (b'<?xml version="1.0"?><!-- SPDX-License-Identifier: BSD-3-Clause '
             b'only intended to be used -->'
             b'<project><parent><groupId>com.sun.activation</groupId>'
             b'<artifactId>all</artifactId><version>1.2.1</version></parent>'
             b'<groupId>jakarta.activation</groupId>'
             b'<artifactId>jakarta.activation-api</artifactId></project>')
    parent = (b'<project><groupId>com.sun.activation</groupId>'
              b'<artifactId>all</artifactId><version>1.2.1</version>'
              b'<licenses><license><name>EDL 1.0</name>'
              b'<url>http://www.eclipse.org/org/documents/edl-v10.php</url>'
              b'</license></licenses></project>')
    licence = (b'Copyright (c) 2018 Oracle\n'
               b'Redistribution and use in source and binary forms\n'
               b'Neither the name of the Eclipse Foundation\n')
    notice = (b'# Notices for Eclipse Project\n'
              b'Eclipse Distribution License v. 1.0\n'
              b'SPDX-License-Identifier: BSD-3-Clause\n')
    jar = archive(licence, notice)
    blobs = {
        auditlib.CHILD_POM: child, auditlib.PARENT_POM: parent,
        auditlib.CHILD_JAR: jar, auditlib.TAG_LICENSE: licence,
        auditlib.TAG_NOTICE: notice, auditlib.TAG_API_POM: child,
    }
    expected = {u:auditlib._git_blob_sha1(blobs[u])
                for u in auditlib.TAG_BLOBS}
    cached = [
        {"filename": "jakarta.activation-api-1.2.1.pom",
         "sha256": auditlib._sha(child), "byteSize": len(child),
         "sourceVerification": "LOCAL_BYTES_ONLY"},
        {"filename": "jakarta.activation-api-1.2.1.jar",
         "sha256": auditlib._sha(jar), "byteSize": len(jar),
         "sourceVerification": "LOCAL_BYTES_ONLY"},
    ]
    inventory = {
        "status": "PASS_WITH_GAPS",
        "scope": "Android Gradle root/app buildEnvironment LOCAL cache evidence only",
        "originVerified": False, "licenseApproval": "NOT_VERIFIED",
        "parentLicenseInheritanceVerified": False,
        "releaseApproved": False, "sbomComplete": False,
        "modules": [{
            "purl": auditlib.PURL,
            "scopes": ["root", "app"], "cachedFiles": cached,
            "pomDeclaredLicenses": [],
            "licenseMetadataState": "POM_WITHOUT_DIRECT_LICENSE_NAME",
        }],
    }
    queue = {
        "status": "REVIEW_QUEUE_ONLY_LEGAL_NO_GO",
        "licenseClosure": "NOT_VERIFIED", "releaseApproved": False,
        "parentLicenseInheritanceVerified": False,
        "microsoftSDKBuildToolsExactRedistRights": "NOT_VERIFIED_SEPARATE_GATE",
        "reviewQueue": [
            {"purl": "pkg:maven/example/fixture@"+str(i),
             "licenseApproved": False} for i in range(41)
        ]+[{
            "purl": auditlib.PURL,
            "directPomState": "POM_WITHOUT_DIRECT_LICENSE_NAME",
            "complexParentMetadataReviewRequired": True,
            "complexParentLicenseMetadataNames": [
                "EDL 1.0", "Eclipse Public License v. 2.0",
                "GNU General Public License, version 2 with the GNU Classpath Exception",
            ],
            "licenseApproved": False, "redistributionRightsVerified": False,
            "cachedParentPOMReviewEvidence": [{
                "coordinate": auditlib.PARENT_COORD, "status": "PARENT_POM_METADATA_ONLY",
                "localPOMSha256": auditlib._sha(parent),
                "unverifiedSupplierLicenseNames": ["EDL 1.0"],
                "licenseApproved": False,
            }, {
                "coordinate": auditlib.COMPANY_ANCESTOR,
                "status": "PARENT_POM_METADATA_ONLY",
                "localPOMSha256": "a"*64,
                "unverifiedSupplierLicenseNames": [
                    "Eclipse Public License v. 2.0",
                    "GNU General Public License, version 2 with the GNU Classpath Exception",
                ],
                "licenseApproved": False,
            }],
        }],
    }
    runtime = {
        "graphAudit": "PASS",
        "scope": "android-:app:debugRuntimeClasspath+debugUnitTestRuntimeClasspath",
        "inventoryCompleteness": "PARTIAL", "pluginClasspathCovered": False,
        "apkPackagingVerified": False, "releaseApproved": False,
        "licenseClosure": "NOT_VERIFIED", "runtimeComponents": [],
        "testComponents": [],
    }
    return inventory, queue, runtime, blobs, expected


class Activation121Tests(unittest.TestCase):
    def setUp(self):
        self.inv, self.queue, self.runtime, self.blobs, self.expected = fixture()

    def result(self):
        return auditlib.audit(
            self.inv, self.queue, self.runtime,
            fetch=lambda u: self.blobs[u], expected_blobs=self.expected)

    def test_valid_synthetic_technical_evidence_still_legal_no_go(self):
        x = self.result()
        self.assertEqual(x["status"],
                         "EXACT_ACTIVATION_API121_SOURCE_BYTES_MATCH_LEGAL_REVIEW_OPEN")
        self.assertEqual(x["declaredLicenseTextForReview"],
                         "EDL-1.0 (supplier tag notice states BSD-3-Clause)")
        self.assertFalse(x["releaseApproved"])
        self.assertFalse(x["licenseOptionSelected"])
        self.assertFalse(x["publisherSignatureVerified"])
        self.assertFalse(x["productRuntimeInclusionVerified"])
        self.assertTrue(x["all42DirectPOMMetadataGapsOpen"])
        self.assertTrue(x["mavenJar"]["embeddedNoticeTagByteParity"])

    def test_root_only_buildtool_scope_is_not_apk(self):
        self.inv["modules"][0]["scopes"] = ["root"]
        self.assertFalse(self.result()["apkPackagingVerified"])

    def test_app_only_buildtool_scope_is_not_apk(self):
        self.inv["modules"][0]["scopes"] = ["app"]
        self.assertFalse(self.result()["apkPackagingVerified"])

    def test_changed_direct_pom_state_rejected(self):
        self.inv["modules"][0]["licenseMetadataState"] = "DIRECT_POM_LICENSE_NAME"
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_forged_supplier_direct_license_rejected(self):
        self.inv["modules"][0]["pomDeclaredLicenses"] = [{"name": "MIT"}]
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_runtime_scope_changed_rejected(self):
        self.inv["modules"][0]["scopes"] = ["runtime"]
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_duplicate_selected_module_rejected(self):
        self.inv["modules"].append(self.inv["modules"][0])
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_local_jar_hash_drift_rejected(self):
        self.inv["modules"][0]["cachedFiles"][1]["sha256"] = "f"*64
        with self.assertRaisesRegex(auditlib.AuditError, "JAR differs"): self.result()

    def test_local_pom_hash_drift_rejected(self):
        self.inv["modules"][0]["cachedFiles"][0]["sha256"] = "f"*64
        with self.assertRaisesRegex(auditlib.AuditError, "POM differs"): self.result()

    def test_duplicate_local_cache_file_rejected(self):
        self.inv["modules"][0]["cachedFiles"].append(
            copy.deepcopy(self.inv["modules"][0]["cachedFiles"][0]))
        with self.assertRaisesRegex(auditlib.AuditError, "duplicate"): self.result()

    def test_missing_parent_pom_sha_rejected(self):
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][0]["localPOMSha256"] = None
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_parent_pom_sha_mismatch_rejected(self):
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][0]["localPOMSha256"] = "f"*64
        with self.assertRaisesRegex(auditlib.AuditError, "parent POM differs"): self.result()

    def test_enterprise_ancestor_must_not_be_child_license(self):
        self.queue["reviewQueue"][-1]["licenseApproved"] = True
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_ancestor_approved_flag_rejected(self):
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][1]["licenseApproved"] = True
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_42_gap_count_silent_shrink_rejected(self):
        self.queue["reviewQueue"].pop(1)
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_product_runtime_appearance_rejected(self):
        self.runtime["runtimeComponents"].append({"purl": auditlib.PURL})
        with self.assertRaisesRegex(auditlib.AuditError, "app/test inclusion"): self.result()

    def test_test_graph_appearance_rejected(self):
        self.runtime["testComponents"].append({"purl": auditlib.PURL})
        with self.assertRaisesRegex(auditlib.AuditError, "app/test inclusion"): self.result()

    def test_apk_package_attestation_rejected(self):
        self.runtime["apkPackagingVerified"] = True
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_publisher_signature_forgery_not_allowed(self):
        self.inv["originVerified"] = True
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_legal_release_forgery_rejected(self):
        self.queue["releaseApproved"] = True
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_wrong_maven_child_parent_rejected(self):
        self.blobs[auditlib.CHILD_POM] = self.blobs[auditlib.CHILD_POM].replace(
            b"<version>1.2.1</version>", b"<version>1.2.2</version>")
        self.inv["modules"][0]["cachedFiles"][0]["sha256"] = auditlib._sha(
            self.blobs[auditlib.CHILD_POM])
        self.inv["modules"][0]["cachedFiles"][0]["byteSize"] = len(
            self.blobs[auditlib.CHILD_POM])
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_unexpected_pom_direct_license_rejected(self):
        self.blobs[auditlib.CHILD_POM] = self.blobs[auditlib.CHILD_POM].replace(
            b"</project>", b"<licenses><license><name>MIT</name></license></licenses></project>")
        f = self.inv["modules"][0]["cachedFiles"][0]
        f["sha256"] = auditlib._sha(self.blobs[auditlib.CHILD_POM])
        f["byteSize"] = len(self.blobs[auditlib.CHILD_POM])
        with self.assertRaises(auditlib.AuditError): self.result()

    def test_issuer_parent_license_mismatch_rejected(self):
        self.blobs[auditlib.PARENT_POM] = self.blobs[auditlib.PARENT_POM].replace(
            b"EDL 1.0", b"Apache-2.0")
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][0][
            "localPOMSha256"] = auditlib._sha(self.blobs[auditlib.PARENT_POM])
        with self.assertRaisesRegex(auditlib.AuditError, "not EDL"): self.result()

    def test_unverified_source_license_change_rejected(self):
        self.blobs[auditlib.TAG_LICENSE] += b"new text"
        with self.assertRaisesRegex(auditlib.AuditError, "Git blob changed"): self.result()

    def test_unverified_notice_change_rejected(self):
        self.blobs[auditlib.TAG_NOTICE] += b"new notice"
        with self.assertRaisesRegex(auditlib.AuditError, "Git blob changed"): self.result()

    def test_unverified_tag_source_pom_change_rejected(self):
        self.blobs[auditlib.TAG_API_POM] += b"new POM"
        with self.assertRaisesRegex(auditlib.AuditError, "Git blob changed"): self.result()

    def test_zip_traversal_rejected(self):
        with self.assertRaisesRegex(auditlib.AuditError, "unsafe JAR"):
            auditlib._archive_legal_texts(archive(
                self.blobs[auditlib.TAG_LICENSE],
                self.blobs[auditlib.TAG_NOTICE], [("../X", b"1")]))

    def test_missing_jar_notice_rejected(self):
        out = BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            z.writestr(auditlib.ARCHIVE_LICENSE, self.blobs[auditlib.TAG_LICENSE])
        with self.assertRaisesRegex(auditlib.AuditError, "missing exact JAR"):
            auditlib._archive_legal_texts(out.getvalue())

    def test_duplicated_jar_legal_file_rejected(self):
        out = BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            z.writestr(auditlib.ARCHIVE_LICENSE, b"a")
            z.writestr(auditlib.ARCHIVE_LICENSE, b"b")
            z.writestr(auditlib.ARCHIVE_NOTICE, b"c")
        with self.assertRaises(auditlib.AuditError):
            auditlib._archive_legal_texts(out.getvalue())

    def test_jar_symlink_rejected(self):
        out = BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            z.writestr(auditlib.ARCHIVE_LICENSE, self.blobs[auditlib.TAG_LICENSE])
            z.writestr(auditlib.ARCHIVE_NOTICE, self.blobs[auditlib.TAG_NOTICE])
            info = zipfile.ZipInfo("META-INF/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "../LICENSE")
        with self.assertRaisesRegex(auditlib.AuditError, "unsafe JAR"):
            auditlib._archive_legal_texts(out.getvalue())

    def test_jar_text_changed_with_hash_reset_fails(self):
        lic = self.blobs[auditlib.TAG_LICENSE] + b"bogus"
        jar = archive(lic, self.blobs[auditlib.TAG_NOTICE])
        self.blobs[auditlib.CHILD_JAR] = jar
        self.inv["modules"][0]["cachedFiles"][1].update(
            sha256=auditlib._sha(jar), byteSize=len(jar))
        with self.assertRaisesRegex(auditlib.AuditError, "embedded LICENSE/NOTICE"):
            self.result()

    def test_wrong_url_not_accepted(self):
        with self.assertRaisesRegex(auditlib.AuditError, "unallowlisted"):
            auditlib.retrieve("https://attacker.test/malicious")

    def test_malformed_doctype_rejected(self):
        with self.assertRaisesRegex(auditlib.AuditError, "unsafe Jakarta"):
            auditlib._child_pom(b"<!DOCTYPE hacked><project/>")

    def test_missing_report_path_fail_closed(self):
        with TemporaryDirectory() as td:
            with self.assertRaises(auditlib.AuditError):
                auditlib._read(Path(td)/"missing.json")


if __name__ == "__main__":
    unittest.main()
