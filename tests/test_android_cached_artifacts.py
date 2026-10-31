"""Synthetic fixtures for local-byte hash audit of selected Maven JARs."""
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_android_cached_artifacts.py"
spec = importlib.util.spec_from_file_location("cached_jars", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
PURL = "pkg:maven/org.example/sample@1.2.3"


def fill(root: Path):
    cache = root / "caches/modules-2/files-2.1"
    jar = cache / "org.example/sample/1.2.3/abcdef/sample-1.2.3.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"synthetic-not-a-real-maven-jar")
    obj = {
        "releaseApproved": False,
        "inventoryCompleteness": "PARTIAL",
        "graphAudit": "PASS",
        "noticeScopeCheck": "PASS",
        "runtimeComponents": [{"purl": PURL}],
        "testComponents": [{"purl": PURL}],
    }
    file = root / "inventory.json"
    file.write_text(json.dumps(obj))
    return file, cache, jar


class AndroidCachedArtifactTests(unittest.TestCase):
    def test_locally_hashed_distinct_modules_not_release_approved(self):
        with TemporaryDirectory() as d:
            inp, cache, jar = fill(Path(d))
            r = mod.inventory(inp, cache)
            self.assertEqual(r["artifactCount"], 1)
            self.assertEqual(r["artifacts"][0]["sha256"], hashlib.sha256(jar.read_bytes()).hexdigest())
            self.assertEqual(r["sourceVerification"], "LOCAL_SHA256_ONLY")
            self.assertFalse(r["releaseApproved"])

    def test_missing_cached_jar_rejected(self):
        with TemporaryDirectory() as d:
            inp, cache, jar = fill(Path(d))
            jar.unlink()
            with self.assertRaises(mod.AuditError):
                mod.inventory(inp, cache)

    def test_ambiguous_cached_jar_rejected(self):
        with TemporaryDirectory() as d:
            inp, cache, jar = fill(Path(d))
            clone = jar.parent.parent / "badd" / jar.name
            clone.parent.mkdir(parents=True)
            clone.write_bytes(jar.read_bytes())
            with self.assertRaises(mod.AuditError):
                mod.inventory(inp, cache)

    def test_forged_release_approval_rejected(self):
        with TemporaryDirectory() as d:
            inp, cache, jar = fill(Path(d))
            v = json.loads(inp.read_text())
            v["releaseApproved"] = True
            inp.write_text(json.dumps(v))
            with self.assertRaises(mod.AuditError):
                mod.inventory(inp, cache)

    def test_missing_notice_review_gate_rejected(self):
        with TemporaryDirectory() as d:
            inp, cache, jar = fill(Path(d))
            v = json.loads(inp.read_text())
            v.pop("noticeScopeCheck")
            inp.write_text(json.dumps(v))
            with self.assertRaises(mod.AuditError):
                mod.inventory(inp, cache)

    def test_symlinked_maven_artifact_rejected(self):
        with TemporaryDirectory() as d:
            inp, cache, jar = fill(Path(d))
            jar.unlink()
            jar.symlink_to("/etc/hosts")
            with self.assertRaises(mod.AuditError):
                mod.inventory(inp, cache)


if __name__ == "__main__":
    unittest.main()
