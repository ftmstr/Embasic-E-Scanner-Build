"""Offline regression suite for one exact kotlinx-serialization-core-jvm 1.7.3 Maven LICENSE/NOTICE source slice.

Synthetic bytes in these tests are NOT genuine Kotlin serialization upstream evidence.
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

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_serialization_core_jvm173_source_review.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("serialization_core_jvm173_source_review", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

RUNTIME = ("> Task :app:dependencies\n"
           "debugRuntimeClasspath - Android scoped resolved graph\n"
           "+--- org.jetbrains.kotlinx:kotlinx-serialization-core-jvm:1.7.3\n"
           "BUILD SUCCESSFUL in 2s\n")
TEST = ("> Task :app:dependencies\n"
        "debugUnitTestRuntimeClasspath - Android JVM tests\n"
        "+--- org.jetbrains.kotlinx:kotlinx-serialization-core-jvm:1.7.3\n"
        "BUILD SUCCESSFUL in 2s\n")
POM = (b"<project><modelVersion>4.0.0</modelVersion>"
       b"<groupId>org.jetbrains.kotlinx</groupId><artifactId>kotlinx-serialization-core-jvm</artifactId>"
       b"<version>1.7.3</version><licenses><license>"
       b"<name>The Apache License, Version 2.0</name>"
       b"</license></licenses></project>")
LICENSE = b"\nApache License\nVersion 2.0\nsynthetic, tests only\n"
NOTICE = b"NOTICE file corresponding to Apache 2.0 for kotlinx.serialization (synthetic)\n"


def jar_bytes(missing: bool = False, zip_slip: bool = False) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("kotlinx/serialization/KSerializer.class", b"\xca\xfe\xba\xbe")
        if not missing:
            archive.writestr("kotlinx/serialization/descriptors/SerialDescriptor.class", b"\xca\xfe\xba\xbe")
        if zip_slip:
            archive.writestr("../unsafe.class", b"x")
        archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
    return stream.getvalue()


def run(pom: bytes = POM, jar: bytes | None = None,
        license_text: bytes = LICENSE, notice_text: bytes = NOTICE,
        cached: bytes | None = None,
        runtime: str = RUNTIME, test: str = TEST,
        blob: str | None = None, notice_blob: str | None = None):
    jar = jar if jar is not None else jar_bytes()
    cached = cached if cached is not None else jar
    blob = blob if blob is not None else m.git_blob(LICENSE)
    notice_blob = notice_blob if notice_blob is not None else m.git_blob(NOTICE)
    return m.audit_bundle(runtime, test, pom, jar, license_text,
                          notice_text, cached, license_blob=blob,
                          notice_blob=notice_blob, expected_shas={
                              "pom": m.digest(pom), "jar": m.digest(jar),
                              "license": m.digest(license_text),
                              "notice": m.digest(notice_text)})


class SerializationCoreJvm173ExactSourceTests(unittest.TestCase):
    def test_synthetic_byte_parity_never_grants_rights(self):
        report = run()
        self.assertEqual(report["purl"], "pkg:maven/org.jetbrains.kotlinx/kotlinx-serialization-core-jvm@1.7.3")
        self.assertEqual(report["status"], "EXACT_MAVEN_TAG_BYTES_MATCH_LEGAL_REVIEW_OPEN")
        self.assertEqual(report["mavenPom"]["sha256"], m.digest(POM))
        self.assertEqual(report["mavenJar"]["sha256"], m.digest(jar_bytes()))
        self.assertEqual(report["taggedLicense"]["sha256"], m.digest(LICENSE))
        self.assertEqual(report["taggedNotice"]["sha256"], m.digest(NOTICE))
        self.assertFalse(report["taggedNotice"]["retainedVerbatimInPublicRepo"])
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

    def test_verified_sha_pins_are_exact_and_synthetic_cannot_replace(self):
        self.assertFalse(run()["sourceHashPinsVerified"])
        self.assertFalse(run()["releaseApproved"])
        self.assertEqual(m.TAG_COMMIT, "d4d066d72a9f92f06c640be5a36a22f75d0d7659")
        self.assertEqual(m.TAG_LICENSE_GIT_BLOB, "9c8f3ea0871e0bfe81da0fa6e7c1d7d156dc380e")
        self.assertEqual(m.TAG_NOTICE_GIT_BLOB, "ee516ec09649791af5ff26c0346e748a881cacb7")
        self.assertEqual(m.PINNED_POM_SHA256,
                         "734f5f749208dd0bef3d98caa594cf9222afdf0fee5b6843347a8fe64e240427")
        self.assertEqual(m.PINNED_JAR_SHA256,
                         "f0adde45864144475385cf4aa7e0b7feb27f61fcf9472665ed98cc971b06b1eb")
        self.assertEqual(m.PINNED_LICENSE_SHA256,
                         "c5accbbd8546e94c34aed24afe689a617627d18eed5a6c48277e48db57c23851")
        self.assertEqual(m.PINNED_NOTICE_SHA256,
                         "ec77bba5c852830abfdefcdefbf4a22577ff4df79ec323a898d5100ca1d6f8d6")
        with self.assertRaisesRegex(m.AuditError, "exact pinned Maven/tag source SHA256 drift"):
            m.audit_bundle(RUNTIME, TEST, POM, jar_bytes(), LICENSE, NOTICE,
                           jar_bytes(), license_blob=m.git_blob(LICENSE),
                           notice_blob=m.git_blob(NOTICE))
        with self.assertRaisesRegex(m.AuditError, "exact pinned Maven/tag source SHA256 drift"):
            m.audit_bundle(RUNTIME, TEST, POM, jar_bytes(), LICENSE, NOTICE,
                           jar_bytes(), license_blob=m.git_blob(LICENSE),
                           notice_blob=m.git_blob(NOTICE),
                           expected_shas={"pom": "0" * 64, "jar": "0" * 64,
                                          "license": "0" * 64, "notice": "0" * 64})

    def test_byte_changed_gradle_cache_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "BYTE_MISMATCH"):
            run(cached=jar_bytes() + b"\0")

    def test_release_tag_license_blob_not_replaceable(self):
        with self.assertRaisesRegex(m.AuditError, "LICENSE blob mismatch"):
            run(license_text=LICENSE + b"tampered")

    def test_tagged_notice_altered_or_omitted_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "NOTICE blob mismatch"):
            run(notice_text=NOTICE + b"tampered")
        with self.assertRaisesRegex(m.AuditError, "NOTICE blob mismatch"):
            run(notice_blob=m.TAG_NOTICE_GIT_BLOB)

    def test_default_real_upstream_sha_is_not_synthetic(self):
        with self.assertRaisesRegex(m.AuditError, "LICENSE blob mismatch"):
            run(blob=m.TAG_LICENSE_GIT_BLOB)

    def test_wrong_maven_version_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "coordinate mismatch"):
            run(pom=POM.replace(b"1.7.3", b"1.7.4"))

    def test_forged_license_label_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "unexpected supplier POM license"):
            run(pom=POM.replace(b"Apache License", b"MIT License"))

    def test_pom_external_entities_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "unsafe XML"):
            run(pom=b"<!DOCTYPE project [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>" + POM)

    def test_missing_gradle_selection_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "not observed"):
            run(runtime=RUNTIME.replace("org.jetbrains.kotlinx:kotlinx-serialization-core-jvm:1.7.3",
                                        "test:unknown:1.7.3"),
                test=TEST.replace("org.jetbrains.kotlinx:kotlinx-serialization-core-jvm:1.7.3",
                                  "test:unknown:1.7.3"))

    def test_jar_invalid_members_and_zip_slip_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "serialization core JVM class signatures absent"):
            run(jar=jar_bytes(missing=True))
        with self.assertRaisesRegex(m.AuditError, "unsafe JAR member"):
            run(jar=jar_bytes(zip_slip=True))

    def test_remote_allowlist_rejects_rogue_endpoint_before_network(self):
        with self.assertRaisesRegex(m.AuditError, "unapproved remote URL"):
            m.official_fetch("https://example.com/example.pom", m.MAX_POM)
        with self.assertRaisesRegex(m.AuditError, "unexpected source bound"):
            m.official_fetch(m.POM_URL, m.MAX_JAR)
        with self.assertRaisesRegex(m.AuditError, "unexpected source bound"):
            m.official_fetch(m.NOTICE_URL, m.MAX_POM)

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
            location = root / "org.jetbrains.kotlinx" / "kotlinx-serialization-core-jvm" / "1.7.3" / "sha"
            location.mkdir(parents=True)
            (location / "kotlinx-serialization-core-jvm-1.7.3.jar").write_bytes(jar_bytes())
            self.assertEqual(m.read_cached_jar(root), jar_bytes())
            (root / "org.jetbrains.kotlinx" / "kotlinx-serialization-core-jvm" / "1.7.3" / "other").mkdir()
            (root / "org.jetbrains.kotlinx" / "kotlinx-serialization-core-jvm" / "1.7.3" / "other" /
             "kotlinx-serialization-core-jvm-1.7.3.jar").write_bytes(jar_bytes())
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
