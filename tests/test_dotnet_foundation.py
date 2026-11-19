"""Synthetic restore fixtures test the PUBLIC Windows foundation fail-closed audit."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_dotnet_foundation.py"
spec = importlib.util.spec_from_file_location("dotnet_audit", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fill(root: Path) -> None:
    for name in mod.PROJECTS:
        p = root / name
        (p / "obj").mkdir(parents=True)
        reference = (
            '<ItemGroup><ProjectReference Include="../Embasic.EScanner.Contracts/'
            'Embasic.EScanner.Contracts.csproj" /></ItemGroup>'
            if name.endswith("SelfTest") else ""
        )
        source = (f'<Project Sdk="Microsoft.NET.Sdk">'
                  f'<PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>'
                  f'{reference}</Project>')
        (p / (name + ".csproj")).write_text(source, encoding="utf-8")
        libs = ({"Embasic.EScanner.Contracts/1.0.0": {"type": "project"}}
                if name.endswith("SelfTest") else {})
        (p / "obj" / "project.assets.json").write_text(
            json.dumps({"targets": {"net10.0": {}}, "libraries": libs}),
            encoding="utf-8",
        )


class DotnetFoundationAuditTests(unittest.TestCase):
    def test_three_project_restore_is_scoped_not_release(self):
        with TemporaryDirectory() as d:
            fill(Path(d))
            result = mod.audit(Path(d))
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["externalNuGetPackageCount"], 0)
            self.assertEqual(len(result["projects"]), 3)
            self.assertFalse(result["releaseApproved"])
            self.assertFalse(result["nativeGuiVerified"])
            self.assertEqual(result["licenseClosure"], "NOT_VERIFIED")

    def test_external_nuget_dependency_is_blocked(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            fill(root)
            p = root / "Embasic.EScanner.Contracts/obj/project.assets.json"
            data = json.loads(p.read_text())
            data["libraries"]["evil.dependency/2.1.0"] = {"type": "package"}
            p.write_text(json.dumps(data))
            with self.assertRaises(mod.AuditError):
                mod.audit(root)

    def test_unreviewed_package_reference_is_blocked(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            fill(root)
            p = root / "Embasic.EScanner.Contracts/Embasic.EScanner.Contracts.csproj"
            p.write_text(p.read_text().replace(
                "</Project>", '<ItemGroup><PackageReference Include="Test" Version="1.0" /></ItemGroup></Project>'
            ))
            with self.assertRaises(mod.AuditError):
                mod.audit(root)

    def test_unexpected_target_framework_blocked(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            fill(root)
            p = root / "Embasic.EScanner.Bootstrap/Embasic.EScanner.Bootstrap.csproj"
            p.write_text(p.read_text().replace("net10.0", "net9.0"))
            with self.assertRaises(mod.AuditError):
                mod.audit(root)

    def test_missing_or_invalid_restore_graph_blocked(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            fill(root)
            p = root / "Embasic.EScanner.SelfTest/obj/project.assets.json"
            p.write_text('{"libraries":{}}')
            with self.assertRaises(mod.AuditError):
                mod.audit(root)

    def test_unreviewed_msbuild_import_rejected(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            fill(root)
            p = root / "Embasic.EScanner.Contracts/Embasic.EScanner.Contracts.csproj"
            p.write_text(p.read_text().replace(
                "</Project>", '<Import Project="untrusted.props" /></Project>'
            ))
            with self.assertRaises(mod.AuditError):
                mod.audit(root)

    def test_missing_restore_file_is_blocked(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            fill(root)
            p = root / "Embasic.EScanner.SelfTest/obj/project.assets.json"
            p.unlink()
            with self.assertRaises(mod.AuditError):
                mod.audit(root)


if __name__ == "__main__":
    unittest.main()
