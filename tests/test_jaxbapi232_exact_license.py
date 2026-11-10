"""Fail-closed 2.3.2 JAXB API version-tag JAR/LICENSE/NOTICE review.

Synthetic-only fixtures; do not ship third-party source licensing text here.
"""
from __future__ import annotations

from copy import deepcopy
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
spec = importlib.util.spec_from_file_location("jaxbapi232_audit", SCRIPTS / "audit_jaxbapi232_exact_license.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def jar(lic: bytes, notice: bytes, extras=()):
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/LICENSE.md", lic)
        z.writestr("META-INF/NOTICE.md", notice)
        for name, contents in extras:
            z.writestr(name, contents)
    return stream.getvalue()


def fixture():
    child = (
        b'<?xml version="1.0"?><!-- SPDX-License-Identifier: BSD-3-Clause -->'
        b'<project><parent><groupId>jakarta.xml.bind</groupId>'
        b'<artifactId>jakarta.xml.bind-api-parent</artifactId><version>2.3.2</version></parent>'
        b'<artifactId>jakarta.xml.bind-api</artifactId></project>'
    )
    parent = (
        b'<project><parent><groupId>org.eclipse.ee4j</groupId>'
        b'<artifactId>project</artifactId><version>1.0.5</version></parent>'
        b'<groupId>jakarta.xml.bind</groupId><artifactId>jakarta.xml.bind-api-parent</artifactId>'
        b'<version>2.3.2</version><licenses><license>'
        b'<name>Eclipse Distribution License - v 1.0</name>'
        b'<url>http://www.eclipse.org/org/documents/edl-v10.php</url>'
        b'</license></licenses></project>'
    )
    lic = (b'Copyright (c) SYNTHETIC Oracle fixture\n'
           b'Redistribution and use in source and binary forms\n'
           b'Neither the name of the Eclipse Foundation\n')
    notice = (b'# Notices for Eclipse Implementation of JAXB\n'
              b'Eclipse Distribution License v. 1.0\n'
              b'SPDX-License-Identifier: BSD-3-Clause\n')
    rawjar = jar(lic, notice)
    blobs = {mod.CHILD_POM: child, mod.PARENT_POM: parent,
             mod.CHILD_JAR: rawjar, mod.TAG_LICENSE: lic,
             mod.TAG_NOTICE: notice, mod.TAG_CHILD_POM: child,
             mod.TAG_PARENT_POM: parent}
    expected = {u:mod._git_blob_sha1(blobs[u]) for u in mod.TAG_BLOBS}
    inv = {"status": "PASS_WITH_GAPS",
           "scope": "Android Gradle root/app buildEnvironment LOCAL cache evidence only",
           "licenseApproval": "NOT_VERIFIED", "originVerified": False,
           "parentLicenseInheritanceVerified": False, "sbomComplete": False,
           "releaseApproved": False,
           "modules": [{
               "purl": mod.PURL,
               "licenseMetadataState": "POM_WITHOUT_DIRECT_LICENSE_NAME",
               "pomDeclaredLicenses": [], "scopes": ["root", "app"],
               "cachedFiles": [
                   {"filename": "jakarta.xml.bind-api-2.3.2.pom",
                    "sha256": mod._sha(child), "byteSize": len(child),
                    "sourceVerification": "LOCAL_BYTES_ONLY"},
                   {"filename": "jakarta.xml.bind-api-2.3.2.jar",
                    "sha256": mod._sha(rawjar), "byteSize": len(rawjar),
                    "sourceVerification": "LOCAL_BYTES_ONLY"},
               ]}]}
    q = {"status": "REVIEW_QUEUE_ONLY_LEGAL_NO_GO",
         "licenseClosure": "NOT_VERIFIED", "releaseApproved": False,
         "parentLicenseInheritanceVerified": False,
         "microsoftSDKBuildToolsExactRedistRights": "NOT_VERIFIED_SEPARATE_GATE",
         "reviewQueue": [
             {"purl": "pkg:maven/synthetic/fixture"+str(i)+"@1",
              "licenseApproved": False, "redistributionRightsVerified": False,
              "parentLicenseInheritanceVerified": False, "evidenceOnly": True}
             for i in range(41)
         ]+[{"purl": mod.PURL, "directPomState": "POM_WITHOUT_DIRECT_LICENSE_NAME",
              "complexParentMetadataReviewRequired": True,
              "complexParentLicenseMetadataNames": [
                  "Eclipse Distribution License - v 1.0",
                  "Eclipse Public License v. 2.0",
                  "GNU General Public License, version 2 with the GNU Classpath Exception",
              ], "licenseApproved": False, "redistributionRightsVerified": False,
              "parentLicenseInheritanceVerified": False, "evidenceOnly": True,
              "cachedParentPOMReviewEvidence": [
                  {"coordinate": mod.PARENT, "status": "PARENT_POM_METADATA_ONLY",
                   "unverifiedSupplierLicenseNames": ["Eclipse Distribution License - v 1.0"],
                   "localPOMSha256": mod._sha(parent), "licenseApproved": False},
                  {"coordinate": mod.ANCESTOR, "status": "PARENT_POM_METADATA_ONLY",
                   "unverifiedSupplierLicenseNames": [
                       "Eclipse Public License v. 2.0",
                       "GNU General Public License, version 2 with the GNU Classpath Exception",
                   ], "localPOMSha256": "a"*64, "licenseApproved": False},
              ]}]}
    rt = {"graphAudit": "PASS",
          "scope": "android-:app:debugRuntimeClasspath+debugUnitTestRuntimeClasspath",
          "inventoryCompleteness": "PARTIAL", "pluginClasspathCovered": False,
          "apkPackagingVerified": False, "licenseClosure": "NOT_VERIFIED",
          "releaseApproved": False, "runtimeComponents": [], "testComponents": []}
    return inv, q, rt, blobs, expected


class JaxbApi232ExactTests(unittest.TestCase):
    def setUp(self):
        self.inv, self.queue, self.rt, self.blobs, self.hashes = fixture()

    def check(self):
        return mod.audit(self.inv, self.queue, self.rt,
                         fetch=lambda u:self.blobs[u], expected_blobs=self.hashes)

    def test_synthetic_legal_text_byte_parity_does_not_confer_rights(self):
        e = self.check()
        self.assertEqual(e["status"], "EXACT_ISTACK308_MAVEN_TAG_LICENSE_NOTICE_PARITY_LEGAL_REVIEW_OPEN")
        self.assertTrue(e["mavenJar"]["embeddedLicenseNoticeTagByteParity"])
        self.assertTrue(e["mavenChildPOM"]["tagSourceByteParity"])
        self.assertFalse(e["publisherSignatureVerified"])
        self.assertFalse(e["licenseOptionSelected"])
        self.assertFalse(e["releaseApproved"])
        self.assertFalse(e["redistributionRightsVerified"])
        self.assertTrue(e["all42ChildPOMReviewGapsOpen"])

    def test_root_only_buildtool_is_not_apk(self):
        self.inv["modules"][0]["scopes"] = ["root"]
        self.assertFalse(self.check()["productRuntimeInclusionVerified"])

    def test_app_only_buildtool_is_not_apk(self):
        self.inv["modules"][0]["scopes"] = ["app"]
        self.assertFalse(self.check()["apkPackagingVerified"])

    def test_duplicate_purl_rejected(self):
        self.inv["modules"].append(deepcopy(self.inv["modules"][0]))
        with self.assertRaises(mod.AuditError):self.check()

    def test_runtime_scope_forged_rejected(self):
        self.inv["modules"][0]["scopes"] = ["runtime"]
        with self.assertRaises(mod.AuditError):self.check()

    def test_direct_child_license_forged_rejected(self):
        self.inv["modules"][0]["pomDeclaredLicenses"] = [{"name":"MIT"}]
        with self.assertRaises(mod.AuditError):self.check()

    def test_parent_metadata_applicability_forged_rejected(self):
        self.inv["parentLicenseInheritanceVerified"] = True
        with self.assertRaises(mod.AuditError):self.check()

    def test_other_legal_row_approval_rejected(self):
        self.queue["reviewQueue"][0]["licenseApproved"] = True
        with self.assertRaisesRegex(mod.AuditError, "forged license"):self.check()

    def test_other_legal_row_redistribution_claim_rejected(self):
        self.queue["reviewQueue"][0]["redistributionRightsVerified"] = True
        with self.assertRaises(mod.AuditError):self.check()

    def test_duplicate_other_legal_purl_rejected(self):
        self.queue["reviewQueue"][1]["purl"] = self.queue["reviewQueue"][0]["purl"]
        with self.assertRaisesRegex(mod.AuditError, "duplicated"):self.check()

    def test_missing_42nd_legal_row_rejected(self):
        self.queue["reviewQueue"].pop()
        with self.assertRaisesRegex(mod.AuditError, "42"):self.check()

    def test_exact_parent_approval_rejected(self):
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][0]["licenseApproved"] = True
        with self.assertRaises(mod.AuditError):self.check()

    def test_ancestor_enterprise_approval_rejected(self):
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][1]["licenseApproved"] = True
        with self.assertRaises(mod.AuditError):self.check()

    def test_exact_parent_cached_sha_drift_rejected(self):
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][0]["localPOMSha256"] = "b"*64
        with self.assertRaisesRegex(mod.AuditError, "cached SHA"):self.check()

    def test_exact_ancestor_sha_invalid_rejected(self):
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][1]["localPOMSha256"] = "bad"
        with self.assertRaises(mod.AuditError):self.check()

    def test_local_pom_bytes_mismatch_rejected(self):
        self.inv["modules"][0]["cachedFiles"][0]["sha256"] = "b"*64
        with self.assertRaisesRegex(mod.AuditError, "Maven bytes"):self.check()

    def test_local_jar_bytes_mismatch_rejected(self):
        self.inv["modules"][0]["cachedFiles"][1]["sha256"] = "b"*64
        with self.assertRaisesRegex(mod.AuditError, "Maven bytes"):self.check()

    def test_duplicate_local_file_rejected(self):
        self.inv["modules"][0]["cachedFiles"].append(deepcopy(self.inv["modules"][0]["cachedFiles"][0]))
        with self.assertRaises(mod.AuditError):self.check()

    def test_changed_child_parent_version_rejected(self):
        self.blobs[mod.CHILD_POM] = self.blobs[mod.CHILD_POM].replace(
            b"<version>2.3.2</version>", b"<version>3.0.9</version>")
        local = self.inv["modules"][0]["cachedFiles"][0]
        local["sha256"] = mod._sha(self.blobs[mod.CHILD_POM])
        local["byteSize"] = len(self.blobs[mod.CHILD_POM])
        with self.assertRaises(mod.AuditError):self.check()

    def test_extra_direct_child_license_rejected(self):
        self.blobs[mod.CHILD_POM] = self.blobs[mod.CHILD_POM].replace(
            b"</project>", b"<licenses><license><name>MIT</name></license></licenses></project>")
        local = self.inv["modules"][0]["cachedFiles"][0]
        local["sha256"] = mod._sha(self.blobs[mod.CHILD_POM])
        local["byteSize"] = len(self.blobs[mod.CHILD_POM])
        with self.assertRaises(mod.AuditError):self.check()

    def test_tagged_source_pom_drift_rejected(self):
        self.blobs[mod.TAG_CHILD_POM] += b"altered"
        with self.assertRaisesRegex(mod.AuditError, "Git blob identity"):self.check()

    def test_tagged_parent_pom_drift_rejected(self):
        self.blobs[mod.TAG_PARENT_POM] += b"altered"
        with self.assertRaisesRegex(mod.AuditError, "Git blob identity"):self.check()

    def test_tagged_license_drift_rejected(self):
        self.blobs[mod.TAG_LICENSE] += b"altered"
        with self.assertRaisesRegex(mod.AuditError, "Git blob identity"):self.check()

    def test_tagged_notice_drift_rejected(self):
        self.blobs[mod.TAG_NOTICE] += b"altered"
        with self.assertRaisesRegex(mod.AuditError, "Git blob identity"):self.check()

    def test_embedded_license_changed_but_rehashed_rejected(self):
        altered = jar(self.blobs[mod.TAG_LICENSE]+b"malicious", self.blobs[mod.TAG_NOTICE])
        self.blobs[mod.CHILD_JAR] = altered
        self.inv["modules"][0]["cachedFiles"][1].update(
            sha256=mod._sha(altered),byteSize=len(altered))
        with self.assertRaisesRegex(mod.AuditError, "embedded legal-text"):self.check()

    def test_embedded_notice_changed_but_rehashed_rejected(self):
        altered = jar(self.blobs[mod.TAG_LICENSE], self.blobs[mod.TAG_NOTICE]+b"malicious")
        self.blobs[mod.CHILD_JAR] = altered
        self.inv["modules"][0]["cachedFiles"][1].update(
            sha256=mod._sha(altered),byteSize=len(altered))
        with self.assertRaisesRegex(mod.AuditError, "embedded legal-text"):self.check()

    def test_jar_missing_notice_rejected(self):
        with zipfile.ZipFile(BytesIO(self.blobs[mod.CHILD_JAR])) as z:
            license_bytes = z.read("META-INF/LICENSE.md")
        out = BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            z.writestr("META-INF/LICENSE.md", license_bytes)
        with self.assertRaises(mod.AuditError):mod._archive_legal_texts(out.getvalue())

    def test_jar_zip_path_traversal_rejected(self):
        with self.assertRaisesRegex(mod.AuditError, "unsafe JAR"):
            mod._archive_legal_texts(jar(self.blobs[mod.TAG_LICENSE],
                                         self.blobs[mod.TAG_NOTICE], [("../path", b"x")]))

    def test_jar_zip_symlink_rejected(self):
        out = BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            z.writestr("META-INF/LICENSE.md", self.blobs[mod.TAG_LICENSE])
            z.writestr("META-INF/NOTICE.md", self.blobs[mod.TAG_NOTICE])
            info = zipfile.ZipInfo("META-INF/symlink")
            info.create_system=3
            info.external_attr=(stat.S_IFLNK|0o777)<<16
            z.writestr(info, "../LICENSE")
        with self.assertRaisesRegex(mod.AuditError, "unsafe JAR"):mod._archive_legal_texts(out.getvalue())

    def test_unexpected_runtime_graph_appearance_rejected(self):
        self.rt["runtimeComponents"].append({"purl":mod.PURL})
        with self.assertRaisesRegex(mod.AuditError, "newly selected"):self.check()

    def test_unexpected_test_graph_appearance_rejected(self):
        self.rt["testComponents"].append({"purl":mod.PURL})
        with self.assertRaisesRegex(mod.AuditError, "newly selected"):self.check()

    def test_forged_apk_verification_rejected(self):
        self.rt["apkPackagingVerified"] = True
        with self.assertRaises(mod.AuditError):self.check()

    def test_unallowlisted_network_url_rejected(self):
        with self.assertRaisesRegex(mod.AuditError, "nonallowlisted"):
            mod.retrieve("https://attacker.invalid/malicious")

    def test_malformed_source_pom_rejected(self):
        with self.assertRaisesRegex(mod.AuditError, "unsafe"):
            mod._child_pom(b"<!DOCTYPE evil><project/>")

    def test_missing_json_input_fails_closed(self):
        with TemporaryDirectory() as td:
            with self.assertRaises(mod.AuditError):mod._read(Path(td)/"missing.json")


if __name__=="__main__":
    unittest.main()
