#!/usr/bin/env python3
"""Synthetic guardrails only; real Maven/Gradle bytes are checked by CI."""
import importlib.util
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit_kotlin_stdlib_2321_source_review.py"
spec = importlib.util.spec_from_file_location("stdlib_audit", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

POM = b'<project><groupId>org.jetbrains.kotlin</groupId><artifactId>kotlin-stdlib</artifactId><version>2.3.21</version><licenses><license><name>Apache License, Version 2.0</name></license></licenses></project>'


def jar_bytes():
    file = BytesIO()
    with zipfile.ZipFile(file, "w") as z:
        z.writestr("kotlin/Unit.class", b"synthetic")
    return file.getvalue()


class TestKotlinStdlibSourceProbe(unittest.TestCase):
    def test_supplier_pom_label_not_grant(self):
        self.assertIn("Apache", mod.validate_pom(POM))

    def test_malformed_or_entity_pom_rejected(self):
        for raw in (b"<!DOCTYPE x [<!ENTITY y 'x'>]>" + POM, b"<project", POM.replace(b"2.3.21", b"2.3.20")):
            with self.subTest(raw=raw[:20]), self.assertRaises(mod.AuditError):
                mod.validate_pom(raw)

    def test_official_url_allowlist(self):
        with self.assertRaises(mod.AuditError):
            mod.fetch("https://example.com/malicious.jar")

    def test_local_maven_parity_and_notice_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "cache"
            folder = cache / "org.jetbrains.kotlin" / "kotlin-stdlib" / "2.3.21" / "hash"
            folder.mkdir(parents=True)
            local = jar_bytes()
            (folder / "kotlin-stdlib-2.3.21.jar").write_bytes(local)
            reports = []
            for name in ("runtime", "test"):
                p = root / (name + ".txt")
                p.write_text("org.jetbrains.kotlin:kotlin-stdlib:2.3.21\nBUILD SUCCESSFUL\n")
                reports.append(p)
            sources = {mod.POM: POM, mod.JAR: local,
                       mod.LICENSE: b"Apache License Version 2.0",
                       mod.NOTICE: b"Kotlin Compiler distribution"}
            result = mod.audit(cache, *reports, get=sources.__getitem__)
            self.assertTrue(result["mavenJAR"]["gradleByteParity"])
            self.assertFalse(result["releaseApproved"])
            self.assertEqual(result["taggedNotice"]["appliesToStdlibJar"], "NOT_VERIFIED_COMPILER_SCOPE")
            sources[mod.JAR] = local + b"altered"
            with self.assertRaises(mod.AuditError):
                mod.audit(cache, *reports, get=sources.__getitem__)


if __name__ == "__main__":
    unittest.main()
