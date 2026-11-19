"""Closed-world adversarial regressions for JAF 1.2.0 tag/POM/JAR licensing bytes.

All samples are generated, synthetic bytes. No downloaded legal texts or
proprietary UYAP material are stored in this test source.
"""
from __future__ import annotations

from io import BytesIO
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "audit_jaf120_exact_license.py"
spec = importlib.util.spec_from_file_location("jaf_120_audit", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fake_license():
    return (b"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) Version 1.1\n"
            b"The GNU General Public License (GPL) Version 2\n"
            b"CLASSPATH EXCEPTION\nSYNTHETIC, NOT A LICENCE TEXT\n")


def jar(licence: bytes, *, extra: list[tuple[str, bytes]] | None = None) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/LICENSE.txt", licence)
        for name, blob in extra or []:
            archive.writestr(name, blob)
    return buf.getvalue()


def sample():
    licence = fake_license()
    child_pom = (
        b"<project><parent><groupId>com.sun.activation</groupId>"
        b"<artifactId>all</artifactId><version>1.2.0</version></parent>"
        b"<groupId>com.sun.activation</groupId><artifactId>javax.activation</artifactId>"
        b"<packaging>jar</packaging></project>")
    parent_pom = (
        b"<project><groupId>com.sun.activation</groupId><artifactId>all</artifactId>"
        b"<version>1.2.0</version><licenses><license>"
        b"<name>CDDL/GPLv2+CE</name>"
        b"<url>https://github.com/javaee/activation/blob/master/LICENSE.txt</url>"
        b"<comments>CDDL or GPL version 2 plus the Classpath Exception</comments>"
        b"</license></licenses></project>")
    files = {module.CHILD_POM: child_pom, module.PARENT_POM: parent_pom,
             module.CHILD_JAR: jar(licence), module.TAG_LICENSE: licence}
    tagged_blob = module._git_blob_sha1(licence)
    cached = [
        {"filename": "javax.activation-1.2.0.pom",
         "sha256": module._sha(child_pom), "byteSize": len(child_pom),
         "sourceVerification": "LOCAL_BYTES_ONLY"},
        {"filename": "javax.activation-1.2.0.jar",
         "sha256": module._sha(files[module.CHILD_JAR]),
         "byteSize": len(files[module.CHILD_JAR]),
         "sourceVerification": "LOCAL_BYTES_ONLY"}]
    inventory = {
        "status": "PASS_WITH_GAPS", "licenseApproval": "NOT_VERIFIED",
        "parentLicenseInheritanceVerified": False,
        "originVerified": False, "releaseApproved": False,
        "modules": [{
            "purl": module.TARGET,
            "licenseMetadataState": "POM_WITHOUT_DIRECT_LICENSE_NAME",
            "pomDeclaredLicenses": [],
            "scopes": ["app", "root"],
            "cachedFiles": cached,
        }],
    }
    queue = {
        "status": "REVIEW_QUEUE_ONLY_LEGAL_NO_GO",
        "licenseClosure": "NOT_VERIFIED",
        "releaseApproved": False,
        "parentLicenseInheritanceVerified": False,
        "microsoftSDKBuildToolsExactRedistRights": "NOT_VERIFIED_SEPARATE_GATE",
        "reviewQueue": [{
            "purl": f"pkg:maven/com.example/fixture{i}@1",
            "licenseApproved": False
        } for i in range(41)] + [{
            "purl": module.TARGET,
            "directPomState": "POM_WITHOUT_DIRECT_LICENSE_NAME",
            "complexParentMetadataReviewRequired": True,
            "complexParentLicenseMetadataNames": ["CDDL/GPLv2+CE"],
            "licenseApproved": False, "redistributionRightsVerified": False,
            "cachedParentPOMReviewEvidence": [{
                "coordinate": module.PARENT,
                "status": "PARENT_POM_METADATA_ONLY",
                "unverifiedSupplierLicenseNames": ["CDDL/GPLv2+CE"],
                "localPOMSha256": module._sha(parent_pom),
                "licenseApproved": False,
            }],
        }],
    }
    runtime = {
        "graphAudit": "PASS",
        "scope": "android-:app:debugRuntimeClasspath+debugUnitTestRuntimeClasspath",
        "inventoryCompleteness": "PARTIAL",
        "pluginClasspathCovered": False,
        "apkPackagingVerified": False,
        "licenseClosure": "NOT_VERIFIED",
        "releaseApproved": False,
        "runtimeComponents": [{"purl": "pkg:maven/example/synthetic@1"}],
        "testComponents": [],
    }
    return inventory, queue, runtime, files, tagged_blob


def run_sample(inventory, queue, runtime, files, tagged_blob):
    return module.audit(inventory, queue, runtime,
                        fetch=lambda u: files[u], expected_tag_blob=tagged_blob)


class JAF120LicenceAuditTests(unittest.TestCase):
    def setUp(self):
        self.inventory, self.queue, self.runtime, self.files, self.blob = sample()

    def run_audit(self):
        return run_sample(self.inventory, self.queue,
                          self.runtime, self.files, self.blob)

    def test_synthetic_exact_tag_and_embedded_license_parity_is_not_legal_approval(self):
        r = self.run_audit()
        self.assertEqual(r["status"],
                         "EXACT_JAF120_SOURCE_BYTES_AND_LICENSE_TEXT_MATCH_REVIEW_OPEN")
        self.assertTrue(r["mavenJAR"]["matchesLocalGradleCache"])
        self.assertTrue(r["embeddedLicense"]["matchesExactTaggedLicenseBytes"])
        self.assertFalse(r["licenseOptionSelected"])
        self.assertFalse(r["parentLicenseInheritanceVerified"])
        self.assertFalse(r["publisherSignatureVerified"])
        self.assertFalse(r["releaseApproved"])
        self.assertEqual(r["licenseClosure"], "NOT_VERIFIED")
        self.assertTrue(r["all42ChildLicenseReviewGapsOpen"])

    def test_child_direct_license_forgery_fails(self):
        self.inventory["modules"][0]["pomDeclaredLicenses"] = [{"name": "MIT"}]
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_scope_runtime_forgery_fails(self):
        self.inventory["modules"][0]["scopes"] = ["runtime"]
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_scope_root_only_is_buildtool(self):
        self.inventory["modules"][0]["scopes"] = ["root"]
        # BuildEnvironment does not imply APK embedding.
        self.assertFalse(self.run_audit()["productRuntimeInclusionVerified"])

    def test_duplicate_target_module_fails(self):
        self.inventory["modules"].append(self.inventory["modules"][0])
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_queue_not_42_fails(self):
        self.queue["reviewQueue"].pop()
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_queue_approves_license_fails(self):
        self.queue["reviewQueue"][-1]["licenseApproved"] = True
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_parent_cached_sha_mismatch_fails(self):
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][0][
            "localPOMSha256"] = "0"*64
        with self.assertRaisesRegex(module.AuditError, "parent POM bytes differ"):
            self.run_audit()

    def test_parent_selected_declared_license_forgery_fails(self):
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][0][
            "unverifiedSupplierLicenseNames"] = ["MIT"]
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_jar_cache_sha_mismatch_fails(self):
        self.inventory["modules"][0]["cachedFiles"][1]["sha256"] = "a"*64
        with self.assertRaisesRegex(module.AuditError, "official JAF JAR bytes differ"):
            self.run_audit()

    def test_child_pom_cache_sha_mismatch_fails(self):
        self.inventory["modules"][0]["cachedFiles"][0]["sha256"] = "b"*64
        with self.assertRaisesRegex(module.AuditError, "official child POM bytes differ"):
            self.run_audit()

    def test_wrong_child_pom_version_or_artifact_fails(self):
        self.files[module.CHILD_POM] = self.files[module.CHILD_POM].replace(
            b"javax.activation", b"evil.activation")
        self.inventory["modules"][0]["cachedFiles"][0]["sha256"] = module._sha(
            self.files[module.CHILD_POM])
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_child_pom_with_direct_license_is_unreviewed_delta(self):
        self.files[module.CHILD_POM] = self.files[module.CHILD_POM].replace(
            b"</project>", b"<licenses><license><name>MIT</name></license></licenses></project>")
        self.inventory["modules"][0]["cachedFiles"][0]["sha256"] = module._sha(
            self.files[module.CHILD_POM])
        self.inventory["modules"][0]["cachedFiles"][0]["byteSize"] = len(
            self.files[module.CHILD_POM])
        with self.assertRaisesRegex(module.AuditError, "direct licence gap"):
            self.run_audit()

    def test_parent_license_swapped_fails(self):
        self.files[module.PARENT_POM] = self.files[module.PARENT_POM].replace(
            b"CDDL/GPLv2+CE", b"Apache-2.0")
        self.queue["reviewQueue"][-1]["cachedParentPOMReviewEvidence"][0][
            "localPOMSha256"] = module._sha(self.files[module.PARENT_POM])
        with self.assertRaisesRegex(module.AuditError, "supplier licence declaration"):
            self.run_audit()

    def test_upstream_release_tag_blob_spoof_fails(self):
        self.files[module.TAG_LICENSE] += b"Malicious untrusted change"
        with self.assertRaisesRegex(module.AuditError, "tagged JAF"):
            self.run_audit()

    def test_incompatible_embedded_license_bytes_fails(self):
        self.files[module.CHILD_JAR] = jar(fake_license()+b"CHANGED")
        self.inventory["modules"][0]["cachedFiles"][1]["sha256"] = module._sha(
            self.files[module.CHILD_JAR])
        self.inventory["modules"][0]["cachedFiles"][1]["byteSize"] = len(
            self.files[module.CHILD_JAR])
        with self.assertRaisesRegex(module.AuditError, "embedded JAF licence bytes differ"):
            self.run_audit()

    def test_missing_archive_license_fails(self):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("com/example/Synthetic.class", b"fake")
        with self.assertRaisesRegex(module.AuditError, "missing/ambiguous"):
            module._embedded_license(buf.getvalue())

    def test_path_traversal_in_jar_fails(self):
        with self.assertRaisesRegex(module.AuditError, "unsafe JAR"):
            module._embedded_license(jar(fake_license(), extra=[("../BAD", b"a")]))

    def test_absolute_file_in_jar_fails(self):
        with self.assertRaisesRegex(module.AuditError, "unsafe JAR"):
            module._embedded_license(jar(fake_license(), extra=[("/etc/passwd", b"a")]))

    def test_duplicate_archive_license_fails(self):
        with patch("warnings.warn"):  # zipfile signals duplicate in synthetic fixture
            with self.assertRaisesRegex(module.AuditError, "unsafe JAR"):
                module._embedded_license(jar(fake_license(), extra=[
                    ("META-INF/LICENSE.txt", b"fake")]))
    
    def test_symlink_archive_file_fails(self):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("META-INF/LICENSE.txt", fake_license())
            info = zipfile.ZipInfo("META-INF/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "../LICENSE")
        with self.assertRaisesRegex(module.AuditError, "unsafe JAR"):
            module._embedded_license(buf.getvalue())

    def test_pom_doctype_fails(self):
        with self.assertRaisesRegex(module.AuditError, "unsafe"):
            module._pom(b'<!DOCTYPE x><project/>', "com.sun.activation",
                        "all", "1.2.0")

    def test_nonallowlisted_network_url_fails(self):
        with self.assertRaisesRegex(module.AuditError, "nonallowlisted"):
            module.retrieve("https://attacker.invalid/jar")

    def test_oversized_response_fails(self):
        self.files[module.CHILD_JAR] = b"x"*(module.ALLOWED[module.CHILD_JAR]+1)
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_runtime_selected_jaf_fails(self):
        self.runtime["runtimeComponents"].append({"purl": module.TARGET})
        with self.assertRaisesRegex(module.AuditError, "app runtime/test scope"):
            self.run_audit()

    def test_test_scope_selected_jaf_fails(self):
        self.runtime["testComponents"].append({"purl": module.TARGET})
        with self.assertRaisesRegex(module.AuditError, "app runtime/test scope"):
            self.run_audit()

    def test_forged_apk_packaging_gate_fails(self):
        self.runtime["apkPackagingVerified"] = True
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_untrusted_parent_inheritance_fails(self):
        self.inventory["parentLicenseInheritanceVerified"] = True
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_jaf_queue_elevated_redist_fails(self):
        self.queue["reviewQueue"][-1]["redistributionRightsVerified"] = True
        with self.assertRaises(module.AuditError):
            self.run_audit()

    def test_missing_cli_inputs_fail_closed(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self.assertRaises(module.AuditError):
                module._read(base/"missing.json")


if __name__ == "__main__":
    unittest.main()
