#!/usr/bin/env python3
"""Read-only PUBLIC .NET 10 restore inventory; NOT a license or release approval.

Checks all three foundation csproj files and their actual NuGet restore assets.
Covers direct PackageReference and resolved 'libraries' only, not the framework
SDK, global.json/MSBuild extensions, NuGet feeds, WinUI 3, binary origin or SBOM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

PROJECTS = (
    "Embasic.EScanner.Contracts",
    "Embasic.EScanner.SelfTest",
    "Embasic.EScanner.Bootstrap",
)
MAX_SIZE = 8_000_000


class AuditError(ValueError):
    pass


def bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AuditError("missing or symlinked .NET source/restore input")
    if path.stat().st_size > MAX_SIZE:
        raise AuditError("oversized .NET source/restore input")
    return path.read_bytes()


def audit(root: Path) -> dict:
    root = Path(root)
    projects = []
    external: list[dict] = []
    for name in PROJECTS:
        project = root / name
        source_path = project / (name + ".csproj")
        data = bounded(source_path)
        try:
            xml = ET.fromstring(data)
        except ET.ParseError as exc:
            raise AuditError("malformed .NET project XML") from exc
        if xml.attrib.get("Sdk") != "Microsoft.NET.Sdk":
            raise AuditError("unexpected SDK for .NET foundation")
        for tag in ("Import", "PackageReference", "PackageVersion",
                    "GlobalPackageReference", "Reference", "Analyzer"):
            if any(elem.tag == tag for elem in xml.iter()):
                raise AuditError("unreviewed package/import/reference source input")
        frameworks = [node.text.strip() for node in xml.iter()
                      if node.tag == "TargetFramework" and node.text]
        if frameworks != ["net10.0"]:
            raise AuditError("unexpected or missing .NET target framework")
        for node in xml.iter("ProjectReference"):
            ref = node.attrib.get("Include", "").replace("\\", "/")
            if not ref or ref.startswith("/") or ".." not in ref:
                raise AuditError("unexpected project reference")
            if name != "Embasic.EScanner.SelfTest" or not ref.endswith(
                "../Embasic.EScanner.Contracts/Embasic.EScanner.Contracts.csproj"
            ):
                raise AuditError("unreviewed project reference")
        assets_path = project / "obj" / "project.assets.json"
        blob = bounded(assets_path)
        try:
            assets = json.loads(blob)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AuditError("unreadable NuGet restore assets") from exc
        libraries = assets.get("libraries")
        if not isinstance(libraries, dict) or not assets.get("targets"):
            raise AuditError("missing resolved NuGet restore graph")
        for coordinate, metadata in libraries.items():
            kind = metadata.get("type")
            if kind != "project":
                external.append({
                    "project": name,
                    "coordinate": coordinate,
                    "type": kind,
                })
        projects.append({
            "name": name,
            "targetFramework": "net10.0",
            "restoreAssetsSha256": hashlib.sha256(blob).hexdigest(),
            "externalNuGetPackages": sum(1 for x in external if x["project"] == name),
        })
    if external:
        raise AuditError("unreviewed third-party NuGet package in foundation restore")
    return {
        "schemaVersion": 1,
        "scope": "PUBLIC-Windows-.NET10-three-foundation-projects",
        "status": "PASS",
        "externalNuGetPackageCount": 0,
        "projects": projects,
        "limitations": [
            "NuGet framework reference packs and SDK are not covered",
            "WinUI3 Windows App SDK is not included or verified",
            "Build/restore output is not a signed package or SBOM",
        ],
        "licenseClosure": "NOT_VERIFIED",
        "nativeGuiVerified": False,
        "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = audit(args.windows_root)
    except (AuditError, OSError) as exc:
        print("BLOCKED: .NET foundation dependency audit: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
