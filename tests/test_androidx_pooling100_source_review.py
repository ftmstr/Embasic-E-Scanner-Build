import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_androidx_pooling100_source_review as a

def archive(name, data, extra=None):
    f = io.BytesIO()
    with zipfile.ZipFile(f, "w") as z:
        z.writestr(name, data)
        if extra:
            z.writestr(extra, b"fixture")
    return f.getvalue()

class PoolingTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        self.cache = self.root / "cache"
        self.jar = self.cache / "androidx.customview/customview-poolingcontainer/1.0.0/hash/customview-poolingcontainer-1.0.0.aar"
        self.jar.parent.mkdir(parents=True)
        self.runtime = self.root / "runtime"
        self.test = self.root / "test"
        self.runtime.write_text("+--- " + a.GAV + "\nBUILD SUCCESSFUL\n")
        self.test.write_text("BUILD SUCCESSFUL\n")
        self.data = {"pom": b"<project><groupId>androidx.customview</groupId><artifactId>customview-poolingcontainer</artifactId><version>1.0.0</version><licenses><license><name>Apache 2.0</name></license></licenses></project>",
                     "aar": archive("classes.jar", archive(a.CLASS, b"\xca\xfe\xba\xbe"), "AndroidManifest.xml"),
                     "sources": archive(a.SOURCE, b'@file:JvmName("PoolingContainer")\nLicensed under the Apache License, Version 2.0'),
                     "license": b"synthetic license"}
        self.jar.write_bytes(self.data["aar"])
    def run_audit(self):
        return a.audit(self.cache, self.runtime, self.test, self.data.__getitem__,
                       license_pin=a.sha(b"synthetic license"),
                       published_pins={k: a.sha(self.data[k]) for k in ("pom", "aar", "sources")})
    def test_scope(self):
        result = self.run_audit()
        self.assertTrue(result["gradleByteParity"])
        self.assertEqual(result["binary"]["classesJar"]["marker"], a.CLASS)
        self.assertFalse(result["releaseApproved"])
        self.assertFalse(result["hashPinsVerified"])
        self.assertEqual(result["releaseNoticeClosure"], "NOT_VERIFIED")
    def test_nested_archive_rejected(self):
        self.data["aar"] = archive("classes.jar", archive(a.CLASS, b"\xca\xfe\xba\xbe", "../bad"), "AndroidManifest.xml")
        self.jar.write_bytes(self.data["aar"])
        with self.assertRaises(a.AuditError):
            self.run_audit()

    def test_missing_manifest(self):
        self.data["aar"] = archive("classes.jar", archive(a.CLASS, b"\xca\xfe\xba\xbe"))
        self.jar.write_bytes(self.data["aar"])
        with self.assertRaises(a.AuditError):
            self.run_audit()

    def test_empty_manifest(self):
        f = io.BytesIO()
        with zipfile.ZipFile(f, "w") as z:
            z.writestr("classes.jar", archive(a.CLASS, b"\xca\xfe\xba\xbe"))
            z.writestr("AndroidManifest.xml", b"")
        self.data["aar"] = f.getvalue()
        self.jar.write_bytes(self.data["aar"])
        with self.assertRaisesRegex(a.AuditError, "empty AAR manifest"):
            self.run_audit()

    def test_wrong_kotlin_jvm_name(self):
        self.data["sources"] = archive(a.SOURCE, b"Licensed under the Apache License, Version 2.0")
        with self.assertRaisesRegex(a.AuditError, "Kotlin JVM name missing"):
            self.run_audit()

    def test_published_pin_drift(self):
        pins = {k: a.sha(self.data[k]) for k in ("pom", "aar", "sources")}
        for kind in pins:
            changed = dict(self.data)
            changed[kind] += b"changed"
            with self.subTest(kind=kind), self.assertRaisesRegex(a.AuditError, "pin mismatch"):
                a.verify_published_pins(changed, pins)
        with self.assertRaisesRegex(a.AuditError, "incomplete"):
            a.verify_published_pins(self.data, {"pom": pins["pom"]})

    def test_mismatch(self):
        self.jar.write_bytes(b"wrong")
        with self.assertRaises(a.AuditError):
            self.run_audit()
    def test_wrong_gav(self):
        self.data["pom"] = self.data["pom"].replace(b"1.0.0", b"0.9.0")
        with self.assertRaises(a.AuditError):
            self.run_audit()
    def test_redirected_graph(self):
        self.runtime.write_text(a.GAV + " -> 1.1.0\nBUILD SUCCESSFUL\n")
        with self.assertRaises(a.AuditError):
            self.run_audit()
    def test_traversal(self):
        self.data["sources"] = archive(a.SOURCE, b'@file:JvmName("PoolingContainer")\nLicensed under the Apache License, Version 2.0', "../bad")
        with self.assertRaises(a.AuditError):
            self.run_audit()
    def test_wrong_license(self):
        self.data["license"] = b"different"
        with self.assertRaises(a.AuditError):
            self.run_audit()
    def test_ambiguous_cache(self):
        other = self.jar.parent.parent / "other" / self.jar.name
        other.parent.mkdir()
        other.write_bytes(self.data["aar"])
        with self.assertRaises(a.AuditError):
            self.run_audit()

if __name__ == "__main__":
    unittest.main()
