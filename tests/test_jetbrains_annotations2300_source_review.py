#!/usr/bin/env python3
"""Synthetic security regressions; not evidence of actual official source bytes."""
from io import BytesIO
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import json
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit_jetbrains_annotations2300_source_review.py"
spec = importlib.util.spec_from_file_location("annotations_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

POM = (b"<project><groupId>org.jetbrains</groupId><artifactId>annotations</artifactId>"
       b"<version>23.0.0</version><licenses><license><name>The Apache Software License, "
       b"Version 2.0</name></license></licenses></project>")
LEGAL = b"Apache License\nVersion 2.0\n"
def make_jar():
    out = BytesIO()
    with zipfile.ZipFile(out, "w") as jar:
        jar.writestr("org/jetbrains/annotations/NotNull.class", b"synthetic-not-real")
    return out.getvalue()

def tree(notice=False):
    entries = [{"path": "LICENSE.txt", "type": "blob", "sha": audit.LICENSE_BLOB}]
    if notice:
        entries.append({"path": "src/NOTICE.txt", "type": "blob", "sha": "a" * 40})
    return json.dumps({"sha": audit.TAG_COMMIT, "truncated": False, "tree": entries}).encode()


class TestAnnotationsSourceAudit(unittest.TestCase):
    def test_pom_exact_coordinate_and_supplier_claim(self):
        self.assertIn("Apache", audit.validate_pom(POM))
        for raw in (POM.replace(b"23.0.0", b"23.0.1"),
                    POM.replace(b"org.jetbrains", b"org.attacker"),
                    b"<!DOCTYPE x [<!ENTITY e 'evil'>]>" + POM, b"<project>",
                    POM.replace(b"<licenses>", b"<bad>").replace(b"</licenses>", b"</bad>")):
            with self.subTest(raw=raw[:32]), self.assertRaises(audit.AuditError):
                audit.validate_pom(raw)

    def test_tagged_legal_notice_absence_and_tree_invariants(self):
        self.assertEqual(audit.validate_tag_tree(tree()), 1)
        for bad in (tree(True), tree().replace(b'"truncated": false', b'"truncated": true'),
                    tree().replace(audit.TAG_COMMIT.encode(), b"a" * 40),
                    tree().replace(audit.LICENSE_BLOB.encode(), b"b" * 40)):
            with self.subTest(bad=bad[:70]), self.assertRaises(audit.AuditError):
                audit.validate_tag_tree(bad)

    def test_jar_signature_and_crc(self):
        source = make_jar()
        self.assertEqual(audit.validate_jar(source), [])
        self.assertRaises(audit.AuditError, audit.validate_jar, b"no-archive")

    def test_allowlist_does_not_fetch_foreign_urls(self):
        self.assertRaises(audit.AuditError, audit.fetch, "https://example.org/redirect")

    def test_bounded_live_provenance_simulation_and_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cache = root / "cache"
            cached = cache / "org.jetbrains" / "annotations" / "23.0.0" / "hash"
            cached.mkdir(parents=True)
            jar = make_jar()
            (cached / "annotations-23.0.0.jar").write_bytes(jar)
            runtime, testing = root / "runtime.txt", root / "test.txt"
            runtime.write_text("BUILD SUCCESSFUL\n", encoding="utf-8")
            testing.write_text("org.jetbrains:annotations:23.0.0\nBUILD SUCCESSFUL\n", encoding="utf-8")
            sources = {audit.POM: POM, audit.JAR: jar, audit.LICENSE: LEGAL, audit.TAG_TREE: tree()}
            with mock.patch.object(audit, "LICENSE_BLOB", audit.blob(LEGAL)):
                # Independently validate the test tree against the modified pinned blob.
                sources[audit.TAG_TREE] = json.dumps({"sha": audit.TAG_COMMIT, "truncated": False,
                    "tree": [{"path": "LICENSE.txt", "type": "blob", "sha": audit.blob(LEGAL)}]}).encode()
                evidence = audit.audit(cache, runtime, testing, get=sources.__getitem__)
                self.assertTrue(evidence["mavenJAR"]["gradleByteParity"])
                self.assertTrue(evidence["selectedGradleGraphs"]["debugUnitTestRuntimeClasspath"])
                self.assertFalse(evidence["selectedGradleGraphs"]["debugRuntimeClasspath"])
                self.assertFalse(evidence["releaseApproved"])
                self.assertEqual(evidence["taggedNotice"]["downstreamNoticeObligations"], "NOT_VERIFIED")
                sources[audit.JAR] = jar + b"tampered"
                self.assertRaises(audit.AuditError, audit.audit, cache, runtime, testing, sources.__getitem__)
                sources[audit.JAR] = jar
                (cached / "annotations-23.0.0.jar").write_bytes(b"bad-local")
                self.assertRaises(audit.AuditError, audit.audit, cache, runtime, testing, sources.__getitem__)


if __name__ == "__main__":
    unittest.main()
