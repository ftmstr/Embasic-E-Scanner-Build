"""Offline regression suite for one exact kotlinx-coroutines-core-jvm 1.8.1 Maven/LICENSE source slice.

Synthetic bytes in these tests are NOT genuine Kotlin coroutines upstream evidence.
Only actual CI HTTPS reads and Gradle cache comparison can establish parity.
"""
from __future__ import annotations

from io import BytesIO
import importlib.util
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_coroutines_core_jvm181_source_review.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("coroutines_core_jvm181_source_review", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

RUNTIME = ("> Task :app:dependencies\n"
           "debugRuntimeClasspath - Android scoped resolved graph\n"
           "+--- org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.8.1\n"
           "BUILD SUCCESSFUL in 2s\n")
TEST = ("> Task :app:dependencies\n"
        "debugUnitTestRuntimeClasspath - Android JVM tests\n"
        "+--- org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.8.1\n"
        "BUILD SUCCESSFUL in 2s\n")
POM = (b"<project><modelVersion>4.0.0</modelVersion>"
       b"<groupId>org.jetbrains.kotlinx</groupId><artifactId>kotlinx-coroutines-core-jvm</artifactId>"
       b"<version>1.8.1</version><licenses><license>"
       b"<name>The Apache License, Version 2.0</name>"
       b"</license></licenses></project>")
LICENSE = b"\nApache License\nVersion 2.0\nsynthetic, tests only\n"


def jar_bytes(missing: bool = False, zip_slip: bool = False) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("kotlinx/coroutines/Job.class", b"\xca\xfe\xba\xbe")
        if not missing:
            archive.writestr("kotlinx/coroutines/BuildersKt.class", b"\xca\xfe\xba\xbe")
        if zip_slip:
            archive.writestr("../unsafe.class", b"x")
        archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
    return stream.getvalue()


def run(pom: bytes = POM, jar: bytes | None = None,
        license_text: bytes = LICENSE, cached: bytes | None = None,
        runtime: str = RUNTIME, test: str = TEST, blob: str | None = None):
    jar = jar if jar is not None else jar_bytes()
    cached = cached if cached is not None else jar
    blob = blob if blob is not None else m.git_blob(LICENSE)
    return m.audit_bundle(runtime, test, pom, jar, license_text, cached,
                          license_blob=blob, expected_shas={
                              "pom": m.digest(pom), "jar": m.digest(jar),
                              "license": m.digest(license_text)})


class CoroutinesCoreJvm181ExactSourceTests(unittest.TestCase):
    def test_synthetic_byte_parity_never_grants_rights(self):
        report = run()
        self.assertEqual(report["purl"], "pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm@1.8.1")
        self.assertEqual(report["status"], "EXACT_MAVEN_TAG_BYTES_MATCH_LEGAL_REVIEW_OPEN")
        self.assertEqual(report["mavenPom"]["sha256"], m.digest(POM))
        self.assertEqual(report["mavenJar"]["sha256"], m.digest(jar_bytes()))
        self.assertEqual(report["taggedLicense"]["sha256"], m.digest(LICENSE))
        self.assertTrue(report["debugRuntimeSelected"])
        self.assertTrue(report["unitTestRuntimeSelected"])
        self.assertFalse(report["releaseApproved"])
        self.assertFalse(report["publisherSignatureVerified"])
        self.assertFalse(report["apkPackagingVerified"])
        self.assertFalse(report["redistributionRightsVerified"])
        self.assertFalse(report["fullRuntimeDependencyNoticeClosure"])
        self.assertTrue(report["independent42PluginPomReviewStillOpen"])
        self.assertFalse(report["sbomComplete"])
        self.assertEqual(report["licenseClosure"], "NOT_VERIFIED")
        self.assertEqual(report["noticeClosure"], "NOT_VERIFIED")

    def test_initial_source_sha_pins_not_fabricated(self):
        self.assertFalse(run()["sourceHashPinsVerified"])
        self.assertFalse(run()["releaseApproved"])
        self.assertEqual(m.TAG_COMMIT, "cd696d3f8f4afdbc735915c2bded974616331b55")
        self.assertEqual(m.TAG_LICENSE_GIT_BLOB, "9c308d958bf91eafe83f66106ca692ff414a4965")
        with self.assertRaisesRegex(m.AuditError, "exact pinned Maven/tag source SHA256 drift"):
            m.audit_bundle(RUNTIME, TEST, POM, jar_bytes(), LICENSE,
                           jar_bytes(), license_blob=m.git_blob(LICENSE),
                           expected_shas={"pom": "0" * 64, "jar": "0" * 64,
                                          "license": "0" * 64})

    def test_byte_changed_gradle_cache_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "BYTE_MISMATCH"):
            run(cached=jar_bytes() + b"\0")

    def test_release_tag_license_blob_not_replaceable(self):
        with self.assertRaisesRegex(m.AuditError, "LICENSE blob mismatch"):
            run(license_text=LICENSE + b"tampered")

    def test_default_real_upstream_sha_is_not_synthetic(self):
        with self.assertRaisesRegex(m.AuditError, "LICENSE blob mismatch"):
            run(blob=m.TAG_LICENSE_GIT_BLOB)

    def test_wrong_maven_version_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "coordinate mismatch"):
            run(pom=POM.replace(b"1.8.1", b"1.8.2"))

    def test_forged_license_label_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "unexpected supplier POM license"):
            run(pom=POM.replace(b"Apache License", b"MIT License"))

    def test_pom_external_entities_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "unsafe XML"):
            run(pom=b"<!DOCTYPE project [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>" + POM)

    def test_missing_gradle_selection_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "not observed"):
            run(runtime=RUNTIME.replace("org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.8.1",
                                        "test:unknown:1.8.1"),
                test=TEST.replace("org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.8.1",
                                  "test:unknown:1.8.1"))

    def test_jar_invalid_members_and_zip_slip_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "core JVM class signatures absent"):
            run(jar=jar_bytes(missing=True))
        with self.assertRaisesRegex(m.AuditError, "unsafe JAR member"):
            run(jar=jar_bytes(zip_slip=True))

    def test_remote_allowlist_rejects_rogue_endpoint_before_network(self):
        with self.assertRaisesRegex(m.AuditError, "unapproved remote URL"):
            m.official_fetch("https://example.com/example.pom", m.MAX_POM)
        with self.assertRaisesRegex(m.AuditError, "unexpected source bound"):
            m.official_fetch(m.POM_URL, m.MAX_JAR)

    def test_cache_missing_or_symlink_is_blocked(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "cache"
            with self.assertRaisesRegex(m.AuditError, "cache missing"):
                m.read_cached_jar(root)
            p = root / "org.jetbrains.kotlinx"
            root.mkdir()
            p.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(m.AuditError, "symlinked Gradle"):
                m.read_cached_jar(root)

    def test_cache_single_exact_jar_bytes_loaded(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            location = root / "org.jetbrains.kotlinx" / "kotlinx-coroutines-core-jvm" / "1.8.1" / "sha"
            location.mkdir(parents=True)
            (location / "kotlinx-coroutines-core-jvm-1.8.1.jar").write_bytes(jar_bytes())
            self.assertEqual(m.read_cached_jar(root), jar_bytes())
            (root / "org.jetbrains.kotlinx" / "kotlinx-coroutines-core-jvm" / "1.8.1" / "other").mkdir()
            (root / "org.jetbrains.kotlinx" / "kotlinx-coroutines-core-jvm" / "1.8.1" / "other" /
             "kotlinx-coroutines-core-jvm-1.8.1.jar").write_bytes(jar_bytes())
            with self.assertRaisesRegex(m.AuditError, "ambiguous"):
                m.read_cached_jar(root)

    def test_cli_missing_inputs_writes_explicit_not_verified(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            result = m.main(["--runtime", str(root / "none"),
                             "--test", str(root / "none2"),
                             "--cache", str(root / "cache"),
                             "--output", str(report)])
            self.assertEqual(result, 2)
            evidence = json.loads(report.read_text())
            self.assertEqual(evidence["status"], "BLOCKED_SOURCE_NOT_VERIFIED")
            self.assertFalse(evidence["releaseApproved"])
            self.assertEqual(evidence["licenseClosure"], "NOT_VERIFIED")
            self.assertFalse(evidence["sbomComplete"])


if __name__ == "__main__":
    unittest.main()
