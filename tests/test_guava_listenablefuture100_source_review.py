#!/usr/bin/env python3
"""Deterministic offline hostile byte/selection tests; no official legal waiver."""
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit_guava_listenablefuture100_source_review.py"
spec = importlib.util.spec_from_file_location("guava_listenablefuture100", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

POM = b"""<?xml version="1.0" encoding="UTF-8"?>
<project><modelVersion>4.0.0</modelVersion>
<parent><groupId>com.google.guava</groupId><artifactId>guava-parent</artifactId>
<version>26.0-android</version></parent>
<artifactId>listenablefuture</artifactId><version>1.0</version>
<description>ListenableFuture 1.0 is real. 9999.0 is empty.</description></project>"""
COPYING = b"Apache License\nVersion 2.0\nSYNTHETIC TEST ONLY\n"
CLASS = "com/google/common/util/concurrent/ListenableFuture.class"


def zip_bytes(entries):
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as output:
        for name, data in entries:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            output.writestr(info, data)
    return stream.getvalue()


def fake_jar(real=True, extra=None):
    entries = [("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")]
    if real:
        entries.append((CLASS, b"\xca\xfe\xba\xbe"))
    if extra is not None:
        entries.append(extra)
    return zip_bytes(entries)


def fake_tree(notice=False):
    entries = [
        {"path": "pom.xml", "type": "blob", "sha": "a" * 40},
        {"path": "src/com/google/common/util/concurrent/ListenableFuture.java",
         "type": "blob", "sha": "b" * 40},
    ] + [{"path": "src/part" + str(i), "type": "tree"} for i in range(6)]
    if notice:
        entries.append({"path": "src/NOTICE.txt", "type": "blob"})
    return json.dumps({"sha": audit.TAG_MODULE_TREE, "truncated": False,
                       "tree": entries}).encode()


class TestGuavaListenableFuture100(unittest.TestCase):
    def test_exact_maven_gav_and_parent_inheritance_not_closed(self):
        parsed = audit.validate_pom(POM)
        self.assertEqual(parsed["version"], "1.0")
        self.assertEqual(parsed["directLicenseClaims"], [])
        self.assertEqual(parsed["inheritedParentLicenseReview"], "NOT_VERIFIED")
        self.assertTrue(parsed["descriptionMentionsRealOneAndEmpty9999"])

    def test_pom_hostile_entities_and_version_confusion_fail_closed(self):
        variants = (POM.replace(b"<version>1.0</version>", b"<version>9999.0-empty-to-avoid-conflict-with-guava</version>"),
                    POM.replace(b"com.google.guava", b"com.attacker"),
                    b'<!DOCTYPE x [<!ENTITY leaky "bad">]>' + POM,
                    POM.replace(b"<artifactId>listenablefuture</artifactId>",
                                b"<artifactId>other</artifactId>"),
                    POM.replace(b"</project>", b""),
                    POM.replace(b"</project>", b"<groupId>duplicate</groupId></project>"))
        for raw in variants:
            with self.subTest(data=raw[:60]), self.assertRaises(audit.ProbeError):
                audit.validate_pom(raw)

    def test_actual_one_jar_required_and_empty_9999_rejected(self):
        self.assertEqual(audit.validate_jar(fake_jar())["classNames"], [CLASS])
        with self.assertRaisesRegex(audit.ProbeError, "empty/placeholder"):
            audit.validate_jar(fake_jar(real=False))

    def test_jar_path_traversal_duplicates_extra_class_and_crc_fail(self):
        for raw in (fake_jar(extra=("../escape", b"evil")),
                    fake_jar(extra=("META-INF/MANIFEST.MF", b"duplicate")),
                    fake_jar(extra=("org/example/Surprise.class", b"CAFE")),
                    fake_jar()[:-10]):
            with self.subTest(length=len(raw)), self.assertRaises((audit.ProbeError, zipfile.BadZipFile)):
                audit.validate_jar(raw)

    def test_tag_tree_scope_is_not_legal_notice_waiver(self):
        parsed = audit.validate_tree(fake_tree())
        self.assertEqual(parsed["sourceToPublishedJarReproducibility"], "NOT_VERIFIED")
        self.assertEqual(parsed["moduleNoticeFilename"], "ABSENT_IN_TAG_MODULE_ONLY")
        for data in (fake_tree(notice=True),
                     fake_tree().replace(audit.TAG_MODULE_TREE.encode(), b"0" * 40),
                     fake_tree().replace(b'"truncated": false', b'"truncated": true')):
            with self.assertRaises(audit.ProbeError):
                audit.validate_tree(data)

    def test_allowlisted_official_source_only(self):
        with self.assertRaises(audit.ProbeError):
            audit.official_fetch("https://example.invalid/guava/listenablefuture-1.0.jar")

    def test_exact_cache_bytes_and_mutation_and_release_no_go(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "cache"
            sub = cache / "com.google.guava" / "listenablefuture" / "1.0" / "digest"
            sub.mkdir(parents=True)
            jar = fake_jar()
            (sub / "listenablefuture-1.0.jar").write_bytes(jar)
            runtime, testing = root / "runtime.txt", root / "test.txt"
            runtime.write_text("com.google.guava:listenablefuture:1.0\nBUILD SUCCESSFUL\n")
            testing.write_text("BUILD SUCCESSFUL\n")
            fake = {audit.POM_URL: POM, audit.JAR_URL: jar,
                    audit.LICENSE_URL: COPYING, audit.TREE_URL: fake_tree()}
            with mock.patch.object(audit, "TAG_COPYING_BLOB", audit.git_blob(COPYING)), \
                 mock.patch.object(audit, "POM_SHA256", audit.sha256(POM)), \
                 mock.patch.object(audit, "JAR_SHA256", audit.sha256(jar)):
                result = audit.audit(cache, runtime, testing, get=fake.__getitem__)
                self.assertTrue(result["officialJAR"]["gradleByteParity"])
                self.assertTrue(result["hashPinsVerified"])
                self.assertFalse(result["releaseApproved"])
                self.assertTrue(result["full85AndroidNoticeRowsStillOpen"])
                self.assertTrue(result["independent42GradlePomGapsOpen"])
                fake[audit.JAR_URL] = jar + b"hostile"
                with self.assertRaises(audit.ProbeError):
                    audit.audit(cache, runtime, testing, get=fake.__getitem__)
                fake[audit.JAR_URL] = jar
                runtime.write_text("com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava\nBUILD SUCCESSFUL\n")
                with self.assertRaisesRegex(audit.ProbeError, "not actually resolved"):
                    audit.audit(cache, runtime, testing, get=fake.__getitem__)

    def test_symlinked_gradle_cache_and_hash_pin_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "cache"
            cache.mkdir()
            (cache / "com.google.guava").symlink_to(cache, target_is_directory=True)
            report = root / "gradle.txt"
            report.write_text("com.google.guava:listenablefuture:1.0\nBUILD SUCCESSFUL\n")
            with self.assertRaises(audit.ProbeError):
                audit.audit(cache, report, report, get=lambda _: b"")
        if audit.POM_SHA256:
            self.assertNotEqual(audit.POM_SHA256, audit.sha256(POM))
        if audit.JAR_SHA256:
            self.assertNotEqual(audit.JAR_SHA256, audit.sha256(fake_jar()))


if __name__ == "__main__":
    unittest.main()
