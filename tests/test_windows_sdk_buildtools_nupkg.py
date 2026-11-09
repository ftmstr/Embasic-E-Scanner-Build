"""Synthetic-only NuGet BuildTools archive/REDIST negative security suite."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

PATH = Path(__file__).resolve().parents[1] / "scripts" / "audit_windows_sdk_buildtools_nupkg.py"
spec = importlib.util.spec_from_file_location("sdk_buildtools_exact", PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

NUSPEC = (b'<package><metadata><id>Microsoft.Windows.SDK.BuildTools</id>'
          b'<version>10.0.26100.4654</version>'
          b'<licenseUrl>https://aka.ms/WinSDKLicenseURL</licenseUrl>'
          b'</metadata></package>')
BASE_FILES = {mod.PACKAGE + ".nuspec": NUSPEC, "tools/tool.dll": b"synthetic bytes"}


def make_zip(files=None):
    files = files or BASE_FILES
    out = io.BytesIO()
    with ZipFile(out, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return out.getvalue()


def fixture(root: Path, files=None):
    root.mkdir(parents=True, exist_ok=True)
    folder = root / mod.PACKAGE / mod.VERSION
    folder.mkdir(parents=True)
    raw = make_zip(files)
    path = folder / (mod.PACKAGE + "." + mod.VERSION + ".nupkg")
    sha = folder / (mod.PACKAGE + "." + mod.VERSION + ".nupkg.sha512")
    path.write_bytes(raw)
    encoded = base64.b64encode(hashlib.sha512(raw).digest()).decode("ascii")
    sha.write_text(encoded, encoding="ascii")
    (folder / ".nupkg.metadata").write_text(
        json.dumps({"version": 2, "contentHash": encoded,
                    "source": "https://api.nuget.org/v3/index.json"}), encoding="utf-8")
    sdk = {
        "purl": mod.PURL,
        "scope": "temporary-WinUI3-restore-only",
        "licenseMetadataStatus": "NO_DIRECT_NUSPEC_LICENSE",
        "supplierLicense": "NOT_VERIFIED",
        "supplierLicenseUrl": mod.LEGACY_URL,
        "publisherVerified": False, "licenseApproved": False,
        "localNuspecSha256": hashlib.sha256(NUSPEC).hexdigest(),
        "nugetSha512Metadata": encoded,
    }
    other = {"purl": "pkg:nuget/microsoft.windowsappsdk@2.6.4"}
    report = {
        "status": "PASS_WITH_GAPS",
        "scope": "disposable Windows SDK 2.6.4 NuGet restore, not E-Scanner runtime",
        "publisherVerified": False, "signedPackageVerified": False,
        "nativeWinuiVerified": False, "licenseClosure": "NOT_VERIFIED",
        "releaseApproved": False, "counts": {"packages": 2},
        "components": [sdk, other],
        "missingDirectLicenseEvidence": [
            {"purl": mod.PURL, "reason": "NO_DIRECT_NUSPEC_LICENSE",
             "supplierLicenseUrl": mod.LEGACY_URL}],
    }
    return report, path, sha


class BuildToolsNuGetEvidenceTests(unittest.TestCase):
    def test_good_archive_integrity_is_not_license_approval(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root)
            result = mod.audit(report, root)
            self.assertEqual(result["status"], "PACKAGE_BYTES_VERIFIED_LICENSE_BLOCKED")
            self.assertTrue(result["rawArchiveHashMatchesCache"])
            self.assertTrue(result["restoreContentHashMatchesMetadata"])
            self.assertTrue(result["nuspecHashMatchesRestore"])
            self.assertEqual(result["purl"], mod.PURL)
            self.assertEqual(result["redistFilenameCandidates"], [])
            self.assertFalse(result["redistributableAssetRightsVerified"])
            self.assertFalse(result["exactVersionLicenseTermsVerified"])
            self.assertFalse(result["releaseApproved"])
            self.assertFalse(result["sbomComplete"])

    def test_redist_filename_is_not_a_legal_grant(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            files = dict(BASE_FILES, **{"REDIST.TXT": b"synthetic file not actual SDK terms"})
            report, _, _ = fixture(root, files)
            result = mod.audit(report, root)
            self.assertEqual(result["redistFilenameCandidates"], ["REDIST.TXT"])
            self.assertFalse(result["redistributionFileListVerified"])
            self.assertFalse(result["redistributableAssetRightsVerified"])

    def test_swapped_archived_bytes_fail_closed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, _ = fixture(root)
            archive.write_bytes(archive.read_bytes() + b"tampered")
            with self.assertRaisesRegex(mod.AuditError, "NUPKG_RAW_ARCHIVE_VS_CACHE_SHA512_MISMATCH"):
                mod.audit(report, root)

    def test_wrong_project_assets_digest_fails_closed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root)
            report["components"][0]["nugetSha512Metadata"] = base64.b64encode(b"x"*64).decode()
            with self.assertRaisesRegex(mod.AuditError, "NUGET_CONTENT_HASH_VS_ASSETS_MISMATCH"):
                mod.audit(report, root)

    def test_wrong_cache_sidecar_digest_fails_closed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, sha = fixture(root)
            sha.write_text(base64.b64encode(b"x"*64).decode())
            with self.assertRaisesRegex(mod.AuditError, "NUPKG_RAW_ARCHIVE_VS_CACHE_SHA512_MISMATCH"):
                mod.audit(report, root)

    def test_malformed_sha512_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, sha = fixture(root)
            sha.write_text("sha512-xxxx")
            with self.assertRaises(mod.AuditError):
                mod.audit(report, root)

    def test_sha512_integrity_prefix_is_accepted(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, sha = fixture(root)
            report["components"][0]["nugetSha512Metadata"] = "sha512-" + sha.read_text()
            result = mod.audit(report, root)
            self.assertTrue(result["packageHashMatchesAssetsAndCache"])

    def test_nuspec_extract_mismatch_fails_closed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            files = dict(BASE_FILES)
            files[mod.PACKAGE + ".nuspec"] = NUSPEC + b"another byte"
            report, _, _ = fixture(root, files)
            with self.assertRaisesRegex(mod.AuditError, "NUPKG_NUSPEC_SHA256_MISMATCH"):
                mod.audit(report, root)

    def test_parent_path_traversal_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root, dict(BASE_FILES, **{"../escape.txt": b"x"}))
            with self.assertRaisesRegex(mod.AuditError, "unsafe NuGet ZIP"):
                mod.audit(report, root)

    def test_zip_entry_with_drive_like_colon_rejected(self):
        # ZipInfo normalizes backslashes on Windows, so use a stable invalid
        # archive path that survives serialization on both operating systems.
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root, dict(BASE_FILES, **{"tools/private:evil.txt": b"x"}))
            with self.assertRaisesRegex(mod.AuditError, "unsafe NuGet ZIP"):
                mod.audit(report, root)

    def test_duplicate_archive_entry_casefold_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root, dict(BASE_FILES, **{"Tools/tool.dll": b"x"}))
            with self.assertRaisesRegex(mod.AuditError, "duplicate NuGet ZIP"):
                mod.audit(report, root)

    def test_zip_symlink_is_refused(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, sidecar = fixture(root)
            buf = io.BytesIO()
            with ZipFile(buf, "w") as package:
                package.writestr(mod.PACKAGE + ".nuspec", NUSPEC)
                entry = ZipInfo("tools/link.dll")
                entry.create_system = 3
                entry.external_attr = (0o120777 << 16)
                package.writestr(entry, "destination")
            blob = buf.getvalue()
            archive.write_bytes(blob)
            checksum = base64.b64encode(hashlib.sha512(blob).digest()).decode()
            sidecar.write_text(checksum)
            report["components"][0]["nugetSha512Metadata"] = checksum
            with self.assertRaisesRegex(mod.AuditError, "symlinked NuGet ZIP"):
                mod.audit(report, root)

    def test_renamed_package_version_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root)
            report["components"][0]["purl"] = "pkg:nuget/microsoft.windows.sdk.buildtools@10.0.26100.4653"
            with self.assertRaisesRegex(mod.AuditError, "missing exact"):
                mod.audit(report, root)

    def test_duplicate_purl_refused(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root)
            report["components"].append(dict(report["components"][0]))
            report["counts"]["packages"] = 3
            with self.assertRaisesRegex(mod.AuditError, "duplicate"):
                mod.audit(report, root)

    def test_unsupported_legacy_url_not_approved(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root)
            report["components"][0]["supplierLicenseUrl"] = "https://example.org/terms"
            with self.assertRaisesRegex(mod.AuditError, "unexpected BuildTools"):
                mod.audit(report, root)

    def test_licence_metadata_must_remain_gap(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root)
            report["components"][0]["licenseMetadataStatus"] = "DIRECT_NUSPEC_LICENSE_UNVERIFIED"
            with self.assertRaises(mod.AuditError):
                mod.audit(report, root)

    def test_forged_release_flag_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root)
            report["releaseApproved"] = True
            with self.assertRaises(mod.AuditError):
                mod.audit(report, root)

    def test_forged_legal_license_claim_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root)
            report["licenseClosure"] = "VERIFIED"
            with self.assertRaises(mod.AuditError):
                mod.audit(report, root)

    def test_bogus_missing_gap_list_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, _, _ = fixture(root)
            report["missingDirectLicenseEvidence"] = []
            with self.assertRaisesRegex(mod.AuditError, "concealed"):
                mod.audit(report, root)

    def test_oversized_package_refused(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, _ = fixture(root)
            with archive.open("ab") as out:
                out.truncate(mod.MAX_ARCHIVE + 1)
            with self.assertRaises(mod.AuditError):
                mod.audit(report, root)

    def test_symlinked_package_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, _ = fixture(root)
            archive.unlink()
            archive.symlink_to("/etc/hosts")
            with self.assertRaises(mod.AuditError):
                mod.audit(report, root)

    def test_missing_archive_refused(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, _ = fixture(root)
            archive.unlink()
            with self.assertRaises(mod.AuditError):
                mod.audit(report, root)

    def test_signed_raw_sha_can_differ_from_nuget_content_hash_without_approval(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, _ = fixture(root)
            meta = archive.parent / ".nupkg.metadata"
            neutral = base64.b64encode(b"n" * 64).decode()
            data = json.loads(meta.read_text())
            data["contentHash"] = neutral
            meta.write_text(json.dumps(data))
            report["components"][0]["nugetSha512Metadata"] = neutral
            result = mod.audit(report, root)
            self.assertTrue(result["rawAndSignatureNeutralDigestsDifferent"])
            self.assertTrue(result["rawArchiveHashMatchesCache"])
            self.assertTrue(result["restoreContentHashMatchesMetadata"])
            self.assertFalse(result["publisherSignatureVerified"])
            self.assertFalse(result["releaseApproved"])

    def test_cache_content_metadata_is_mandatory(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, _ = fixture(root)
            (archive.parent / ".nupkg.metadata").unlink()
            with self.assertRaises(mod.AuditError):
                mod.audit(report, root)

    def test_wrong_signature_neutral_content_hash_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, _ = fixture(root)
            meta = archive.parent / ".nupkg.metadata"
            data = json.loads(meta.read_text())
            data["contentHash"] = base64.b64encode(b"x" * 64).decode()
            meta.write_text(json.dumps(data))
            with self.assertRaisesRegex(mod.AuditError, "NUGET_CONTENT_HASH_VS_ASSETS_MISMATCH"):
                mod.audit(report, root)

    def test_untrusted_nuget_source_hint_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, _ = fixture(root)
            meta = archive.parent / ".nupkg.metadata"
            data = json.loads(meta.read_text())
            data["source"] = "https://evil.example/v3/index.json"
            meta.write_text(json.dumps(data))
            with self.assertRaisesRegex(mod.AuditError, "source hint"):
                mod.audit(report, root)

    def test_future_content_metadata_version_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "packages"
            report, archive, _ = fixture(root)
            meta = archive.parent / ".nupkg.metadata"
            data = json.loads(meta.read_text())
            data["version"] = 999
            meta.write_text(json.dumps(data))
            with self.assertRaisesRegex(mod.AuditError, "metadata version"):
                mod.audit(report, root)

    def test_cli_missing_evidence_is_blocked(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual(mod.main([
                "--restore-report", str(root/"missing.json"),
                "--packages", str(root), "--output", str(root/"out.json")]), 2)


if __name__ == "__main__":
    unittest.main()
