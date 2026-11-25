#!/usr/bin/env python3
"""Offline adversarial tests for one AndroidX Interpolator AAR. Not upstream evidence."""
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit_androidx_startup111_source_review.py"
spec = importlib.util.spec_from_file_location("startup111", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

POM = (b"<project><groupId>androidx.startup</groupId><artifactId>startup-runtime</artifactId>"
       b"<version>1.1.1</version><licenses><license>"
       b"<name>The Apache Software License, Version 2.0</name>"
       b"</license></licenses></project>")
LICENSE = b"Apache License\nVersion 2.0\nSYNTHETIC REGRESSION ONLY\n"


def zip_archive(members):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as out:
        for name, data in members:
            # Do not inherit system time: byte-level hashes must be deterministic.
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_STORED
            out.writestr(entry, data)
    return buffer.getvalue()


def fake_aar(class_file=True, extra=None):
    inner = zip_archive([
        ("androidx/startup/AppInitializer.class", b"CAFE")
    ] if class_file else [("no/class.class", b"broken")])
    entries = [("classes.jar", inner), ("AndroidManifest.xml", b"<manifest/>")]
    if extra is not None:
        entries.append(extra)
    return zip_archive(entries)


def fake_tree(add_notice=False):
    rows = [
        {"path": "api/current.txt", "type": "blob"},
        {"path": "src/main/java/androidx/startup/AppInitializer.java", "type": "blob"},
    ] + [{"path": "src/tree" + str(i), "type": "tree"} for i in range(9)]
    if add_notice:
        rows.append({"path": "src/NOTICE.txt", "type": "blob"})
    return json.dumps({"sha": audit.SOURCE_MODULE_TREE, "truncated": False, "tree": rows}).encode()


class TestStartup111(unittest.TestCase):
    def test_exact_maven_pom_and_claim_not_grant(self):
        self.assertIn("Apache", audit.validate_pom(POM))
        for raw in (POM.replace(b"1.1.1", b"1.0.1"),
                    POM.replace(b"androidx.startup", b"androidx.malicious"),
                    POM.replace(b"Apache Software License", b"MIT License"),
                    b"<!DOCTYPE x [<!ENTITY z 'y'>]>" + POM,
                    b"<project"):
            with self.subTest(fragment=raw[:40]), self.assertRaises(audit.AuditError):
                audit.validate_pom(raw)

    def test_zip_class_and_traversal_fail_closed(self):
        self.assertEqual(audit.validate_aar(fake_aar()), [])
        for raw in (fake_aar(class_file=False),
                    fake_aar(extra=("../traversal", b"x")),
                    fake_aar(extra=("docs/NOTICE.txt", b"synthetic")),):
            if b"NOTICE.txt" in raw:
                self.assertEqual(audit.validate_aar(raw), ["docs/NOTICE.txt"])
            else:
                with self.assertRaises(audit.AuditError):
                    audit.validate_aar(raw)

    def test_pinned_source_tree_and_notice_scope(self):
        self.assertGreaterEqual(audit.validate_source_tree(fake_tree()), 10)
        for raw in (fake_tree(True), fake_tree().replace(audit.SOURCE_MODULE_TREE.encode(), b"f" * 40),
                    fake_tree().replace(b'"truncated": false', b'"truncated": true')):
            with self.assertRaises(audit.AuditError):
                audit.validate_source_tree(raw)

    def test_strict_url_allowlist(self):
        with self.assertRaises(audit.AuditError):
            audit.official_fetch("https://evil.example/startup-runtime-1.1.1.aar")

    def test_real_hash_pins_must_not_match_fake_archive(self):
        if audit.AAR_SHA256:
            self.assertNotEqual(audit.AAR_SHA256, audit.digest(fake_aar()))
        if audit.POM_SHA256:
            self.assertNotEqual(audit.POM_SHA256, audit.digest(POM))

    def test_synthetic_maven_cache_parity_and_mutation(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            cache = root / "cache"
            folder = cache / "androidx.startup" / "startup-runtime" / "1.1.1" / "digest"
            folder.mkdir(parents=True)
            aar = fake_aar()
            (folder / "startup-runtime-1.1.1.aar").write_bytes(aar)
            runtime, testing = root / "runtime.txt", root / "test.txt"
            runtime.write_text("androidx.startup:startup-runtime:1.1.1\nBUILD SUCCESSFUL\n")
            testing.write_text("BUILD SUCCESSFUL\n")
            fake = {audit.POM_URL: POM, audit.AAR_URL: aar, audit.LICENSE_URL: LICENSE,
                    audit.SOURCE_TREE_URL: fake_tree()}
            with mock.patch.object(audit, "SOURCE_LICENSE_BLOB", audit.blob(LICENSE)), \
                 mock.patch.object(audit, "POM_SHA256", audit.digest(POM)), \
                 mock.patch.object(audit, "AAR_SHA256", audit.digest(aar)):
                result = audit.audit(cache, runtime, testing, get=fake.__getitem__)
                self.assertTrue(result["officialAAR"]["gradleByteParity"])
                self.assertTrue(result["hashPinsVerified"])
                self.assertFalse(result["releaseApproved"])
                self.assertEqual(result["upstreamModule"]["sourceToPublishedAarReproducibility"], "NOT_VERIFIED")
                self.assertTrue(result["android85NoticeRowsOpen"])
                fake[audit.AAR_URL] = aar + b"tampered"
                with self.assertRaises(audit.AuditError):
                    audit.audit(cache, runtime, testing, get=fake.__getitem__)
                fake[audit.AAR_URL] = aar
                testing.write_text("BUILD SUCCESSFUL\n")
                runtime.write_text("BUILD SUCCESSFUL\n")
                with self.assertRaises(audit.AuditError):
                    audit.audit(cache, runtime, testing, get=fake.__getitem__)

    def test_local_symlink_and_missing_aar_fail_closed(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            cache = root / "cache"
            cache.mkdir()
            (cache / "androidx.startup").symlink_to(cache, target_is_directory=True)
            report = root / "gradle.txt"
            report.write_text("androidx.startup:startup-runtime:1.1.1\nBUILD SUCCESSFUL\n")
            with self.assertRaises(audit.AuditError):
                audit.audit(cache, report, report, get=lambda _: b"")
            

if __name__ == "__main__":
    unittest.main()
