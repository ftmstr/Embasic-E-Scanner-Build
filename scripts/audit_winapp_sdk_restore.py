#!/usr/bin/env python3
"""Isolated Windows App SDK NuGet restore evidence. NOT product inclusion.

Accept only a temporary .NET 10 Windows project's resolved assets, check the
exact WindowsAppSDK 2.6.4 pin, collect package-scoped NuGet SHA512 metadata,
local .nuspec SHA256, and untrusted supplier license declarations. Does not
build, run, link, sign or approve a native WinUI application.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

LIMIT = 10_000_000
MAX_PACKAGES = 400
SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\Z")
PIN = "microsoft.windowsappsdk/2.6.4"


class AuditError(ValueError):
    pass


def _read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
        raise AuditError("missing, symlinked or oversized restore evidence")
    return path.read_bytes()


def audit(raw: bytes, packages_root: Path) -> dict:
    if not raw or len(raw) > LIMIT:
        raise AuditError("missing or oversized NuGet lock content")
    try:
        assets = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError("invalid NuGet restore assets") from exc
    libraries = assets.get("libraries")
    targets = assets.get("targets")
    if not isinstance(libraries, dict) or not isinstance(targets, dict) or not targets:
        raise AuditError("no resolved NuGet graph")
    frameworks = list(targets)
    if not all(key.startswith("net10.0-windows") for key in frameworks):
        raise AuditError("unexpected NuGet target framework")
    packages = [(k, v) for k, v in libraries.items() if v.get("type") == "package"]
    if not packages or len(packages) > MAX_PACKAGES:
        raise AuditError("empty or unbounded resolved NuGet packages")
    if sum(1 for k, _ in packages if k.lower() == PIN) != 1:
        raise AuditError("Windows App SDK 2.6.4 package missing or changed")
    if packages_root.is_symlink() or not packages_root.is_dir():
        raise AuditError("unsafe NuGet package cache")

    records = []
    counts = {"packages": len(packages), "nuspecHashed": 0,
              "nuspecMissing": 0, "supplierLicenseDeclarations": 0,
              "sha512Present": 0, "sha512Missing": 0}
    for key, data in sorted(packages, key=lambda x: x[0].lower()):
        if "/" not in key:
            raise AuditError("unbounded NuGet identity")
        name, version = key.rsplit("/", 1)
        if not SAFE.fullmatch(name) or not SAFE.fullmatch(version):
            raise AuditError("unsafe package identity")
        name, version = name.lower(), version.lower()
        folder = packages_root / name / version
        if folder.is_symlink():
            raise AuditError("symlinked NuGet cache package")
        path = folder / (name + ".nuspec")
        record = {
            "purl": f"pkg:nuget/{name}@{version}",
            "scope": "temporary-WinUI3-restore-only",
            "publisherVerified": False, "licenseApproved": False,
            "localNuspecSha256": None, "supplierLicense": "NOT_VERIFIED",
            "nugetSha512Metadata": data.get("sha512") or "NOT_VERIFIED",
        }
        # Broken symlinks return False for exists(); reject before that check.
        if path.is_symlink():
            raise AuditError("symlinked NuGet package metadata")
        if path.exists():
            content = _read(path)
            record["localNuspecSha256"] = hashlib.sha256(content).hexdigest()
            counts["nuspecHashed"] += 1
            try:
                xml = ET.fromstring(content)
                lic = xml.find(".//{*}metadata/{*}license")
                if lic is not None and lic.text and lic.text.strip():
                    record["supplierLicense"] = {
                        "kind": lic.attrib.get("type", "unspecified")[:64],
                        "value": lic.text.strip()[:256],
                        "evidence": "UNVERIFIED_NUGET_NUSPEC",
                    }
                    counts["supplierLicenseDeclarations"] += 1
            except ET.ParseError:
                record["supplierLicense"] = "UNREADABLE_NUSPEC"
        else:
            counts["nuspecMissing"] += 1
        sha512 = data.get("sha512")
        if sha512:
            try:
                # NuGet project.assets.json uses 'sha512-<base64>' package digests.
                if not isinstance(sha512, str) or not sha512.startswith("sha512-"):
                    raise ValueError("missing sha512 metadata prefix")
                if len(base64.b64decode(sha512[7:], validate=True)) != 64:
                    raise ValueError("wrong digest length")
            except (ValueError, base64.binascii.Error) as exc:
                observed_prefix = ("sha512-" if isinstance(sha512, str)
                                   and sha512.startswith("sha512-") else "no-sha512-prefix")
                raise AuditError("invalid NuGet SHA512 for " + name + "/" + version
                                 + ", prefix=" + observed_prefix
                                 + ", charLength=" + str(len(str(sha512)))) from exc
            counts["sha512Present"] += 1
        else:
            counts["sha512Missing"] += 1
        records.append(record)
    return {
        "schemaVersion": 1, "status": "PASS_WITH_GAPS",
        "scope": "disposable Windows SDK 2.6.4 NuGet restore, not E-Scanner runtime",
        "assetsSha256": hashlib.sha256(raw).hexdigest(),
        "targetFrameworks": frameworks, "counts": counts,
        "components": records, "publisherVerified": False,
        "signedPackageVerified": False, "nativeWinuiVerified": False,
        "licenseClosure": "NOT_VERIFIED", "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--assets", type=Path, required=True)
    p.add_argument("--packages", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        report = audit(_read(args.assets), args.packages)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (AuditError, OSError, TypeError, ValueError) as exc:
        print("BLOCKED: WinUI3 isolated package inventory: " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "counts": report["counts"],
                      "nativeWinuiVerified": False, "releaseApproved": False},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
