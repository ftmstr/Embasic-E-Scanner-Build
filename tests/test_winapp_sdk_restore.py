"""Offline synthetic isolated Windows App SDK NuGet restore audit tests."""
from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "audit_winapp_sdk_restore.py"
spec = importlib.util.spec_from_file_location("winappsdk_probe", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
LICENSE = ('<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">'
           '<metadata><license type="expression">MIT</license></metadata></package>')


def setup(root: Path):
    cache = root / "packages"
    cache.mkdir()
    encoded = base64.b64encode(b"x" * 64).decode()
    libraries = {
        "Microsoft.WindowsAppSDK/2.6.4": {"type": "package", "sha512": "sha512-" + encoded},
        "Microsoft.Web.WebView2/1.0.3719.77": {"type": "package", "sha512": "sha512-" + encoded},
    }
    assets = {"libraries": libraries, "targets": {"net10.0-windows10.0.26100.0": {}}}
    path = cache / "microsoft.windowsappsdk" / "2.6.4"
    path.mkdir(parents=True)
    (path / "microsoft.windowsappsdk.nuspec").write_text(LICENSE)
    return assets, cache


class WinAppSDKRestoreAuditTests(unittest.TestCase):
    def test_exact_package_and_unverified_scope(self):
        with TemporaryDirectory() as directory:
            assets, cache = setup(Path(directory))
            result = mod.audit(json.dumps(assets).encode(), cache)
            self.assertEqual(result["counts"]["packages"], 2)
            self.assertEqual(result["counts"]["nuspecHashed"], 1)
            self.assertEqual(result["counts"]["nuspecMissing"], 1)
            self.assertEqual(result["counts"]["sha512Present"], 2)
            self.assertEqual(result["counts"]["supplierLicenseDeclarations"], 1)
            self.assertFalse(result["releaseApproved"])
            self.assertFalse(result["nativeWinuiVerified"])
            self.assertEqual(result["components"][0]["supplierLicense"]["evidence"],
                             "UNVERIFIED_NUGET_NUSPEC")

    def test_wrong_windows_app_sdk_version_fails(self):
        with TemporaryDirectory() as directory:
            assets, cache = setup(Path(directory))
            assets["libraries"]["Microsoft.WindowsAppSDK/2.6.3"] = assets["libraries"].pop(
                "Microsoft.WindowsAppSDK/2.6.4"
            )
            with self.assertRaises(mod.AuditError):
                mod.audit(json.dumps(assets).encode(), cache)

    def test_no_target_windows_framework_rejected(self):
        with TemporaryDirectory() as directory:
            assets, cache = setup(Path(directory))
            assets["targets"] = {"net10.0": {}}
            with self.assertRaises(mod.AuditError):
                mod.audit(json.dumps(assets).encode(), cache)

    def test_unsafe_package_coordinate_rejected(self):
        with TemporaryDirectory() as directory:
            assets, cache = setup(Path(directory))
            assets["libraries"]["../bad"] = {"type": "package", "sha512": "sha512-abc"}
            with self.assertRaises(mod.AuditError):
                mod.audit(json.dumps(assets).encode(), cache)

    def test_bogus_sha512_metadata_rejected(self):
        with TemporaryDirectory() as directory:
            assets, cache = setup(Path(directory))
            assets["libraries"]["Microsoft.WindowsAppSDK/2.6.4"]["sha512"] = "sha512-abc"
            with self.assertRaises(mod.AuditError):
                mod.audit(json.dumps(assets).encode(), cache)

    def test_symlinked_nuspec_rejected(self):
        with TemporaryDirectory() as directory:
            assets, cache = setup(Path(directory))
            path = cache / "microsoft.windowsappsdk" / "2.6.4" / "microsoft.windowsappsdk.nuspec"
            path.unlink()
            path.symlink_to("/etc/hosts")
            with self.assertRaises(mod.AuditError):
                mod.audit(json.dumps(assets).encode(), cache)

    def test_supplier_license_text_cannot_be_release_approval(self):
        with TemporaryDirectory() as directory:
            assets, cache = setup(Path(directory))
            result = mod.audit(json.dumps(assets).encode(), cache)
            for record in result["components"]:
                self.assertFalse(record["licenseApproved"])
                self.assertFalse(record["publisherVerified"])
            self.assertEqual(result["licenseClosure"], "NOT_VERIFIED")

    def test_missing_restore_graph_fails_closed(self):
        with TemporaryDirectory() as directory:
            assets, cache = setup(Path(directory))
            assets["targets"] = {}
            with self.assertRaises(mod.AuditError):
                mod.audit(json.dumps(assets).encode(), cache)


if __name__ == "__main__":
    unittest.main()
