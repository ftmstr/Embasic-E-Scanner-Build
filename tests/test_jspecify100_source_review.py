"""Offline regression suite for one exact JSpecify Maven/LICENSE source slice.

Synthetic bytes in these tests are NOT genuine JSpecify upstream evidence.
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

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_jspecify100_source_review.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("jspecify_source_review", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

RUNTIME = ("> Task :app:dependencies\n"
           "debugRuntimeClasspath - Android scoped resolved graph\n"
           "+--- org.jspecify:jspecify:1.0.0\n"
           "BUILD SUCCESSFUL in 2s\n")
TEST = ("> Task :app:dependencies\n"
        "debugUnitTestRuntimeClasspath - Android JVM tests\n"
        "+--- org.jspecify:jspecify:1.0.0\n"
        "BUILD SUCCESSFUL in 2s\n")
POM = (b"<project><modelVersion>4.0.0</modelVersion>"
       b"<groupId>org.jspecify</groupId><artifactId>jspecify</artifactId>"
       b"<version>1.0.0</version><licenses><license>"
       b"<name>The Apache License, Version 2.0</name>"
       b"</license></licenses></project>")
LICENSE = b"\nApache License\nVersion 2.0\nsynthetic, tests only\n"


def jar_bytes(missing: bool = False, zip_slip: bool = False) -> bytes:
    stream = BytesIO()
    # Pin ZIP entry timestamps: zipfile.writestr(name, bytes) otherwise inserts
    # current local time and breaks cross-second exact SHA checks in CI.
    def deterministic_entry(name: str, value: bytes, archive: zipfile.ZipFile) -> None:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        archive.writestr(info, value)
    with zipfile.ZipFile(stream, "w") as archive:
        deterministic_entry("org/jspecify/annotations/Nullable.class", b"\xca\xfe\xba\xbe", archive)
        if not missing:
            deterministic_entry("org/jspecify/annotations/NullMarked.class", b"\xca\xfe\xba\xbe", archive)
        if zip_slip:
            deterministic_entry("../unsafe.class", b"x", archive)
        deterministic_entry("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", archive)
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


class JspecifyExactSourceTests(unittest.TestCase):
    def test_synthetic_byte_parity_never_grants_rights(self):
        report = run()
        self.assertEqual(report["purl"], "pkg:maven/org.jspecify/jspecify@1.0.0")
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

    def test_real_source_sha_pins_cannot_be_replaced_by_synthetic_bytes(self):
        self.assertEqual(
            m.PINNED_JAR_SHA256,
            "1fad6e6be7557781e4d33729d49ae1cdc8fdda6fe477bb0cc68ce351eafdfbab")
        self.assertEqual(
            m.PINNED_POM_SHA256,
            "cdab929a3b95211f43d2090c5e2d0dfe8465960e378bc32b35841dab324433a6")
        self.assertEqual(
            m.PINNED_LICENSE_SHA256,
            "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30")
        with self.assertRaisesRegex(m.AuditError, "pinned Maven/tag source SHA256 drift"):
            m.audit_bundle(RUNTIME, TEST, POM, jar_bytes(), LICENSE, jar_bytes(),
                           license_blob=m.git_blob(LICENSE))

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
            run(pom=POM.replace(b"1.0.0", b"1.0.1"))

    def test_forged_license_label_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "unexpected supplier POM license"):
            run(pom=POM.replace(b"Apache License", b"MIT License"))

    def test_pom_external_entities_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "unsafe XML"):
            run(pom=b"<!DOCTYPE project [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>" + POM)

    def test_missing_gradle_selection_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "not observed"):
            run(runtime=RUNTIME.replace("org.jspecify:jspecify:1.0.0",
                                        "test:unknown:1.0.0"),
                test=TEST.replace("org.jspecify:jspecify:1.0.0",
                                  "test:unknown:1.0.0"))

    def test_jar_invalid_members_and_zip_slip_rejected(self):
        with self.assertRaisesRegex(m.AuditError, "annotation classes absent"):
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
            p = root / "org.jspecify"
            root.mkdir()
            p.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(m.AuditError, "symlinked Gradle"):
                m.read_cached_jar(root)

    def test_cache_single_exact_jar_bytes_loaded(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            location = root / "org.jspecify" / "jspecify" / "1.0.0" / "sha"
            location.mkdir(parents=True)
            (location / "jspecify-1.0.0.jar").write_bytes(jar_bytes())
            self.assertEqual(m.read_cached_jar(root), jar_bytes())
            (root / "org.jspecify" / "jspecify" / "1.0.0" / "other").mkdir()
            (root / "org.jspecify" / "jspecify" / "1.0.0" / "other" /
             "jspecify-1.0.0.jar").write_bytes(jar_bytes())
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
