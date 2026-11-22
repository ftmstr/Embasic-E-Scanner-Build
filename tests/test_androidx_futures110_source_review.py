#!/usr/bin/env python3
"""Offline synthetic hostile tests for one AndroidX Futures 1.1.0 JAR, not official bytes."""
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit_androidx_futures110_source_review.py"
spec = importlib.util.spec_from_file_location("futures110", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
POM = (b"<project><groupId>androidx.concurrent</groupId><artifactId>concurrent-futures"
       b"</artifactId><version>1.1.0</version><licenses><license>"
       b"<name>The Apache Software License, Version 2.0</name>"
       b"</license></licenses></project>")
NOTICE = b"kotlinx.coroutines\nSYNTHETIC TEST ONLY\n"
LICENSE = b"Apache License Version 2.0\nSYNTHETIC TEST ONLY\n"


def archive(members):
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for path, data in members:
            info = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            out.writestr(info, data)
    return buf.getvalue()


def jar(ok=True, extra=None):
    entries = [("androidx/concurrent/futures/CallbackToFutureAdapter.class", b"\xca\xfe\xba\xbe")]
    if not ok:
        entries = [("not-futures/Absent.class", b"no")]
    if extra:
        entries.append(extra)
    return archive(entries)


def tree(with_notice=True):
    paths = [
        ("src/main/java/androidx/concurrent/futures/CallbackToFutureAdapter.java", "b"*40),
        ("src/main/resources/META-INF/NOTICE.txt", audit.SNAPSHOT_NOTICE_BLOB),
        ("build.gradle", "c"*40)] + [("api/" + str(n), "d"*40) for n in range(17)]
    if not with_notice:
        paths = [x for x in paths if "NOTICE" not in x[0]]
    return json.dumps({"sha": audit.SNAPSHOT_MODULE_TREE, "truncated": False,
                       "tree": [{"path": p, "sha": s, "type": "blob"} for p, s in paths]}).encode()


class TestFutures110(unittest.TestCase):
    def test_pom_exact_coordinates_and_license_claim_is_not_release(self):
        self.assertEqual(audit.validate_pom(POM)["coordinates"], audit.GAV)
        self.assertEqual(audit.validate_pom(POM)["licenseAndNoticeCompleteness"], "NOT_VERIFIED")

    def test_pom_hostile_namespace_duplicate_entity_wrong_version(self):
        for raw in (POM.replace(b"1.1.0", b"1.2.0"),
                    POM.replace(b"androidx.concurrent", b"androidx.attacker"),
                    POM.replace(b"</project>", b"<groupId>duplicate</groupId></project>"),
                    b'<!DOCTYPE doc [<!ENTITY x "evil">]>' + POM,
                    POM[:-20]):
            with self.subTest(raw=raw[:75]), self.assertRaises(audit.AuditError):
                audit.validate_pom(raw)

    def test_jar_requires_real_callback_class_and_crc(self):
        self.assertTrue(audit.validate_jar(jar())["callbackClassPresent"])
        for content in (jar(ok=False), jar(extra=("../escape", b"bad")),
                        jar(extra=("androidx/concurrent/futures/CallbackToFutureAdapter.class", b"dup")),
                        jar()[:-14]):
            with self.subTest(length=len(content)), self.assertRaises((audit.AuditError, zipfile.BadZipFile)):
                audit.validate_jar(content)

    def test_later_source_notice_is_present_not_silently_dropped(self):
        self.assertTrue(audit.validate_tree(tree())["laterSourceNoticePresent"])
        self.assertEqual(audit.validate_tree(tree())["release110NoticeCorrespondence"], "NOT_VERIFIED")
        for source in (tree(with_notice=False),
                       tree().replace(audit.SNAPSHOT_MODULE_TREE.encode(), b"0"*40),
                       tree().replace(b'"truncated": false', b'"truncated": true'),
                       tree().replace(audit.SNAPSHOT_NOTICE_BLOB.encode(), b"1"*40)):
            with self.assertRaises(audit.AuditError):
                audit.validate_tree(source)

    def test_official_fetch_url_allowlist(self):
        with self.assertRaises(audit.AuditError):
            audit.fetch("https://example.invalid/concurrent-futures-1.1.0.jar")

    def test_gradle_byte_parity_pin_and_failed_release_boundaries(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            cache = base / "cache"
            p = cache / "androidx.concurrent" / "concurrent-futures" / "1.1.0" / "digest"
            p.mkdir(parents=True)
            raw_jar = jar()
            (p / "concurrent-futures-1.1.0.jar").write_bytes(raw_jar)
            runtime, test = base / "runtime", base / "test"
            runtime.write_text("androidx.concurrent:concurrent-futures:1.1.0\nBUILD SUCCESSFUL\n")
            test.write_text("BUILD SUCCESSFUL\n")
            sources = {audit.POM_URL: POM, audit.JAR_URL: raw_jar,
                       audit.NOTICE_URL: NOTICE, audit.LICENSE_URL: LICENSE,
                       audit.TREE_URL: tree()}
            with mock.patch.object(audit, "SNAPSHOT_NOTICE_BLOB", audit.blob(NOTICE)), \
                 mock.patch.object(audit, "SNAPSHOT_LICENSE_BLOB", audit.blob(LICENSE)), \
                 mock.patch.object(audit, "POM_SHA256", audit.sha(POM)), \
                 mock.patch.object(audit, "JAR_SHA256", audit.sha(raw_jar)):
                sources[audit.TREE_URL] = tree()  # create fixture after mocked NOTICE blob pin
                result = audit.audit(cache, runtime, test, getter=sources.__getitem__)
                self.assertTrue(result["officialJAR"]["gradleByteParity"])
                self.assertFalse(result["releaseApproved"])
                self.assertEqual(result["laterSourceNotice"]["2020ReleasedJarObligation"], "NOT_VERIFIED")
                self.assertTrue(result["android85MissingNoticeRowsOpen"])
                sources[audit.JAR_URL] = raw_jar + b"hostile"
                with self.assertRaises(audit.AuditError):
                    audit.audit(cache, runtime, test, getter=sources.__getitem__)

    def test_empty_or_wrong_gradle_resolution_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            cache = base / "cache"
            cache.mkdir()
            runtime = base / "runtime"
            runtime.write_text("androidx.concurrent:concurrent-futures:1.2.0\nBUILD SUCCESSFUL\n")
            with self.assertRaises(audit.AuditError):
                audit.audit(cache, runtime, runtime, getter=lambda _: b"")

    def test_reject_gradle_cache_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            cache = base / "cache"
            cache.mkdir()
            (cache / "androidx.concurrent").symlink_to(cache, target_is_directory=True)
            runtime = base / "runtime"
            runtime.write_text("androidx.concurrent:concurrent-futures:1.1.0\nBUILD SUCCESSFUL\n")
            with self.assertRaises(audit.AuditError):
                audit.audit(cache, runtime, runtime, getter=lambda _: b"")


if __name__ == "__main__":
    unittest.main()
