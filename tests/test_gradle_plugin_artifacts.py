"""Closed-world fixtures for bounded plugin cache SHA/POM claim collection."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_gradle_plugin_artifacts.py"
spec = importlib.util.spec_from_file_location("plugin_artifact_audit", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

AGP = "pkg:maven/com.android.tools.build/gradle@8.13.2"
KOTLIN = "pkg:maven/org.jetbrains.kotlin/kotlin-gradle-plugin@2.3.21"
POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
<licenses><license><name>Apache License, Version 2.0</name>
<url>https://www.apache.org/licenses/LICENSE-2.0</url></license></licenses>
</project>"""


def synthetic(root: Path):
    cache = root / "cache"
    cache.mkdir()
    entries = [{"purl": purl, "licenseApproved": False,
                "binaryProvenance": "NOT_VERIFIED"} for purl in (AGP, KOTLIN)]
    graph = {"status": "PASS", "inventoryCompleteness": "PARTIAL",
             "releaseApproved": False, "artifactHashesCovered": False,
             "pluginBinaryLicensesVerified": False,
             "root": entries, "app": [],
             "moduleCounts": {"root": 2, "app": 0}}
    inp = root / "plugin-graph.json"
    inp.write_text(json.dumps(graph))
    directory = cache / "com.android.tools.build" / "gradle" / "8.13.2" / ("a" * 40)
    directory.mkdir(parents=True)
    jar = directory / "gradle-8.13.2.jar"
    jar.write_bytes(b"synthetic-only-not-real-gradle-binary")
    pom = directory / "gradle-8.13.2.pom"
    pom.write_text(POM)
    return inp, cache, jar, pom


def load(path: Path):
    return json.loads(path.read_text())


class PluginArtifactEvidenceTests(unittest.TestCase):
    def test_missing_module_is_recorded_as_gap_not_approval(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, pom = synthetic(Path(directory))
            result = mod.audit(load(inp), cache)
            self.assertEqual(result["status"], "PASS_WITH_GAPS")
            self.assertEqual(result["counts"]["modules"], 2)
            self.assertEqual(result["counts"]["withLocalBytes"], 1)
            self.assertEqual(result["counts"]["withoutLocalBytes"], 1)
            self.assertFalse(result["originVerified"])
            self.assertFalse(result["releaseApproved"])
            self.assertEqual(result["licenseApproval"], "NOT_VERIFIED")

    def test_actual_sha256_and_untrusted_pom_claim_recorded(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, pom = synthetic(Path(directory))
            result = mod.audit(load(inp), cache)
            agp = next(x for x in result["modules"] if x["purl"] == AGP)
            digests = {file["filename"]: file["sha256"] for file in agp["cachedFiles"]}
            self.assertEqual(digests[jar.name], hashlib.sha256(jar.read_bytes()).hexdigest())
            self.assertEqual(digests[pom.name], hashlib.sha256(pom.read_bytes()).hexdigest())
            self.assertEqual(agp["pomDeclaredLicenses"][0]["evidence"], "UNVERIFIED_SUPPLIER_POM")
            self.assertEqual(result["counts"]["pomWithLicenseNames"], 1)

    def test_modified_jars_get_different_fingerprint(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, _ = synthetic(Path(directory))
            old = mod.audit(load(inp), cache)
            jar.write_bytes(b"changed and not signed")
            new = mod.audit(load(inp), cache)
            self.assertNotEqual(old["modules"][0]["cachedFiles"], new["modules"][0]["cachedFiles"])

    def test_symlinked_module_artifact_is_rejected(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, _ = synthetic(Path(directory))
            jar.unlink()
            jar.symlink_to("/etc/hosts")
            with self.assertRaises(mod.AuditError):
                mod.audit(load(inp), cache)

    def test_unexpected_plugin_version_is_rejected(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            data = load(inp)
            data["root"][0]["purl"] = "pkg:maven/com.android.tools.build/gradle@8.13.1"
            with self.assertRaises(mod.AuditError):
                mod.audit(data, cache)

    def test_path_traversal_as_module_name_is_rejected(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            data = load(inp)
            data["root"].append({"purl": "pkg:maven/org.example/..@1.0",
                                 "licenseApproved": False, "binaryProvenance": "NOT_VERIFIED"})
            data["moduleCounts"]["root"] += 1
            with self.assertRaises(mod.AuditError):
                mod.audit(data, cache)

    def test_tampered_upstream_release_flag_is_rejected(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            data = load(inp)
            data["releaseApproved"] = True
            with self.assertRaises(mod.AuditError):
                mod.audit(data, cache)

    def test_missing_plugin_input_graph_is_rejected(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            data = load(inp)
            data["moduleCounts"]["root"] = 147
            with self.assertRaises(mod.AuditError):
                mod.audit(data, cache)

    def test_duplicate_scope_entry_is_rejected(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            data = load(inp)
            data["root"].append(data["root"][0])
            data["moduleCounts"]["root"] += 1
            with self.assertRaises(mod.AuditError):
                mod.audit(data, cache)

    def test_zero_verified_modules_fails_closed(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, pom = synthetic(Path(directory))
            jar.unlink()
            pom.unlink()
            with self.assertRaises(mod.AuditError):
                mod.audit(load(inp), cache)

    def test_unparseable_pom_is_not_accepted_as_license(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, pom = synthetic(Path(directory))
            pom.write_text("<project><licenses><bad>")
            result = mod.audit(load(inp), cache)
            self.assertEqual(result["counts"]["unreadablePom"], 1)
            self.assertEqual(result["counts"]["pomWithLicenseNames"], 0)
            self.assertFalse(result["releaseApproved"])

    def test_selected_plugin_binary_missing_is_visible_gap(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            result = mod.audit(load(inp), cache)
            kotlin = next(x for x in result["modules"] if x["purl"] == KOTLIN)
            self.assertEqual(kotlin["cacheStatus"], "NO_LOCAL_EVIDENCE")

    def test_correct_partial_notice_counter_is_accepted(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            result = mod.audit(load(inp), cache)
            notice = ("# Partial NOTICE: NOT a complete SBOM\n"
                      "UNVERIFIED_SUPPLIER_POM; releaseApproved=false\n"
                      "- pluginModules: 2\n"
                      "- pluginLicenseNameMetadata: 1\n"
                      "- pluginMissingLicenseMetadata: 1\n"
                      "- pluginCachedFileHashes: 2\n")
            mod.check_partial_notice(result, notice)

    def test_stale_license_count_is_rejected(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            result = mod.audit(load(inp), cache)
            notice = ("NOT a complete SBOM; UNVERIFIED_SUPPLIER_POM; releaseApproved=false\n"
                      "- pluginModules: 2\n"
                      "- pluginLicenseNameMetadata: 2\n"
                      "- pluginMissingLicenseMetadata: 0\n"
                      "- pluginCachedFileHashes: 2\n")
            with self.assertRaises(mod.AuditError):
                mod.check_partial_notice(result, notice)

    def test_duplicate_plugin_hash_counter_is_rejected(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            result = mod.audit(load(inp), cache)
            notice = ("NOT a complete SBOM; UNVERIFIED_SUPPLIER_POM; releaseApproved=false\n"
                      "- pluginModules: 2\n"
                      "- pluginLicenseNameMetadata: 1\n"
                      "- pluginMissingLicenseMetadata: 1\n"
                      "- pluginCachedFileHashes: 2\n"
                      "- pluginCachedFileHashes: 2\n")
            with self.assertRaises(mod.AuditError):
                mod.check_partial_notice(result, notice)

    def test_misleading_complete_notice_is_rejected(self):
        with TemporaryDirectory() as directory:
            inp, cache, _, _ = synthetic(Path(directory))
            result = mod.audit(load(inp), cache)
            with self.assertRaises(mod.AuditError):
                mod.check_partial_notice(result, "ALL LICENSES APPROVED\n")

    def test_pom_missing_is_not_mislabeled_as_no_license_rights(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, pom = synthetic(Path(directory))
            pom.unlink()
            result = mod.audit(load(inp), cache)
            agp = next(x for x in result["modules"] if x["purl"] == AGP)
            self.assertEqual(agp["licenseMetadataState"], "POM_NOT_CACHED")
            self.assertEqual(agp["pomFilesSeen"], 0)
            self.assertEqual(result["counts"]["pomNotCached"], 2)
            self.assertFalse(result["parentLicenseInheritanceVerified"])

    def test_pom_without_direct_license_retains_unverified_parent(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, pom = synthetic(Path(directory))
            pom.write_text('<project xmlns="http://maven.apache.org/POM/4.0.0">'
                           '<parent><groupId>org.example</groupId>'
                           '<artifactId>parent</artifactId>'
                           '<version>1.0</version></parent></project>')
            result = mod.audit(load(inp), cache)
            agp = next(x for x in result["modules"] if x["purl"] == AGP)
            self.assertEqual(agp["licenseMetadataState"], "POM_WITHOUT_DIRECT_LICENSE_NAME")
            self.assertEqual(agp["unresolvedPomParents"], ["org.example:parent:1.0"])
            self.assertEqual(result["counts"]["pomHasUnresolvedParent"], 1)
            self.assertEqual(result["counts"]["pomWithoutDirectLicenseName"], 1)
            self.assertEqual(agp["pomDeclaredLicenses"], [])

    def test_invalid_cached_pom_has_separate_unreadable_status(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, pom = synthetic(Path(directory))
            pom.write_text("<project><unclosed>")
            result = mod.audit(load(inp), cache)
            agp = next(x for x in result["modules"] if x["purl"] == AGP)
            self.assertEqual(agp["licenseMetadataState"], "UNREADABLE_POM")
            self.assertEqual(result["counts"]["unreadablePom"], 1)
            self.assertEqual(len(result["missingDirectLicenseEvidence"]), 2)

    def test_partial_notice_rejects_tampered_license_reason_totals(self):
        with TemporaryDirectory() as directory:
            inp, cache, jar, pom = synthetic(Path(directory))
            result = mod.audit(load(inp), cache)
            notice = ("NOT a complete SBOM; UNVERIFIED_SUPPLIER_POM; releaseApproved=false\\n"
                      "- pluginModules: 2\\n"
                      "- pluginLicenseNameMetadata: 1\\n"
                      "- pluginMissingLicenseMetadata: 1\\n"
                      "- pluginCachedFileHashes: 2\\n")
            result["counts"]["pomNotCached"] = 4
            with self.assertRaises(mod.AuditError):
                mod.check_partial_notice(result, notice)

    def test_oversized_metadata_is_not_accepted(self):
        self.assertEqual(mod._licenses(b"x" * (mod.MAX_METADATA + 1))[0]["name"],
                         "UNREADABLE_OVERSIZE_POM")


if __name__ == "__main__":
    unittest.main()
