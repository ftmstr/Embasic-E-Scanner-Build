#!/usr/bin/env python3
"""Inspect exact Windows SDK BuildTools NuGet cache archive against restore hashes.

EVIDENCE ONLY. A verified NuGet package byte digest, a .nuspec or a REDIST
filename is NOT an SDK redistribution licence, legal approval, publisher
signature, native WinUI test or E-Scanner release approval.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from zipfile import BadZipFile, ZipFile

PURL = "pkg:nuget/microsoft.windows.sdk.buildtools@10.0.26100.4654"
PACKAGE = "microsoft.windows.sdk.buildtools"
VERSION = "10.0.26100.4654"
LEGACY_URL = "https://aka.ms/WinSDKLicenseURL"
MAX_INPUT = 4_000_000
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_FILES = 10000
MAX_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class AuditError(ValueError):
    pass


def _read(path: Path, maximum: int) -> bytes:
    if (path.is_symlink() or not path.is_file()
            or not 0 < path.stat().st_size <= maximum):
        raise AuditError("missing, unsafe or unbounded NuGet evidence")
    return path.read_bytes()


def _sha512_text(raw: str, context: str) -> bytes:
    if not isinstance(raw, str):
        raise AuditError("invalid " + context + " SHA512 type")
    value = raw[7:] if raw.startswith("sha512-") else raw
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AuditError("invalid " + context + " SHA512 base64") from exc
    if len(decoded) != 64:
        raise AuditError("invalid " + context + " SHA512 length")
    return decoded


def _selected(report: dict) -> dict:
    if (not isinstance(report, dict)
            or report.get("status") != "PASS_WITH_GAPS"
            or report.get("scope") != "disposable Windows SDK 2.6.4 NuGet restore, not E-Scanner runtime"
            or report.get("publisherVerified") is not False
            or report.get("signedPackageVerified") is not False
            or report.get("nativeWinuiVerified") is not False
            or report.get("licenseClosure") != "NOT_VERIFIED"
            or report.get("releaseApproved") is not False):
        raise AuditError("untrusted restore scope or forged distribution approval")
    rows = report.get("components")
    counts = report.get("counts")
    if (not isinstance(rows, list) or not isinstance(counts, dict)
            or not 2 <= len(rows) <= 400 or counts.get("packages") != len(rows)):
        raise AuditError("empty or inconsistent selected NuGet graph")
    seen: set[str] = set()
    matches = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("purl"), str):
            raise AuditError("invalid NuGet component evidence")
        if row["purl"] in seen:
            raise AuditError("duplicate selected NuGet coordinate")
        seen.add(row["purl"])
        if row["purl"] == PURL:
            matches.append(row)
    if len(matches) != 1:
        raise AuditError("missing exact Windows SDK BuildTools version")
    row = matches[0]
    if (row.get("scope") != "temporary-WinUI3-restore-only"
            or row.get("licenseMetadataStatus") != "NO_DIRECT_NUSPEC_LICENSE"
            or row.get("supplierLicense") != "NOT_VERIFIED"
            or row.get("supplierLicenseUrl") != LEGACY_URL
            or row.get("publisherVerified") is not False
            or row.get("licenseApproved") is not False
            or not isinstance(row.get("localNuspecSha256"), str)
            or not SHA256.fullmatch(row["localNuspecSha256"])):
        raise AuditError("unexpected BuildTools nuspec metadata or elevated licence claims")
    gaps = report.get("missingDirectLicenseEvidence")
    if (not isinstance(gaps, list) or
            len([g for g in gaps if isinstance(g, dict) and g.get("purl") == PURL
                 and g.get("reason") == "NO_DIRECT_NUSPEC_LICENSE"
                 and g.get("supplierLicenseUrl") == LEGACY_URL]) != 1):
        raise AuditError("BuildTools missing-license gap was concealed")
    _sha512_text(row.get("nugetSha512Metadata"), "restore")
    return row


def _archive_entries(archive: Path, expected_nuspec_hash: str) -> dict:
    try:
        with ZipFile(archive) as package:
            entries = package.infolist()
            if not 0 < len(entries) <= MAX_FILES:
                raise AuditError("empty or excessive NuGet archive entries")
            names: set[str] = set()
            total = 0
            nuspec = []
            redistributable_candidates = []
            other_legal_candidates = []
            for entry in entries:
                name = entry.filename
                parts = name.split("/")
                if (not name or name.startswith("/")
                        or "\\" in name or ":" in name
                        or any(part in ("", ".", "..") for part in parts[:-1])
                        or (parts[-1] in ("", ".", "..") and not entry.is_dir())
                        or "\x00" in name):
                    raise AuditError("unsafe NuGet ZIP entry path")
                key = name.casefold()
                if key in names:
                    raise AuditError("ambiguous duplicate NuGet ZIP entry")
                names.add(key)
                if (entry.create_system == 3
                        and stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFLNK):
                    raise AuditError("symlinked NuGet ZIP entry")
                total += entry.file_size
                if (entry.file_size > MAX_UNCOMPRESSED
                        or total > MAX_UNCOMPRESSED):
                    raise AuditError("unbounded NuGet ZIP uncompressed payload")
                if entry.is_dir():
                    continue
                base = parts[-1].lower()
                if len(parts) == 1 and base == PACKAGE + ".nuspec":
                    nuspec.append(name)
                if base in {"redist.txt", "redist.md", "redistributables.txt",
                            "redistributables.md"}:
                    redistributable_candidates.append(name)
                if (base.startswith("license") or base.startswith("licence")
                        or base.startswith("notice") or base.startswith("third-party")
                        or base.startswith("third_party")):
                    other_legal_candidates.append(name)
            if len(nuspec) != 1:
                raise AuditError("missing or ambiguous exact NuGet package nuspec")
            info = package.getinfo(nuspec[0])
            if info.file_size > 1_000_000:
                raise AuditError("unbounded in-archive nuspec")
            # Only the small nuspec is decompressed; no package tools executed.
            embedded_hash = hashlib.sha256(package.read(nuspec[0])).hexdigest()
            if embedded_hash != expected_nuspec_hash:
                raise AuditError("NUPKG_NUSPEC_SHA256_MISMATCH")
            return {
                "archiveEntryCount": len(entries),
                "archiveUncompressedBytesDeclared": total,
                "embeddedNuspecSha256": embedded_hash,
                "redistFilenameCandidates": sorted(redistributable_candidates),
                "otherLegalFilenameCandidates": sorted(other_legal_candidates),
                "archiveCRCAndEmbeddedBinaryBytesVerified": False,
            }
    except (BadZipFile, EOFError, OSError, RuntimeError) as exc:
        raise AuditError("invalid or inaccessible NuGet package ZIP") from exc


def audit(report: dict, package_root: Path) -> dict:
    row = _selected(report)
    if package_root.is_symlink() or not package_root.is_dir():
        raise AuditError("unsafe NuGet global package root")
    folder = package_root / PACKAGE / VERSION
    if folder.is_symlink() or not folder.is_dir():
        raise AuditError("missing or symlinked exact SDK package cache")
    archive = folder / (PACKAGE + "." + VERSION + ".nupkg")
    hashfile = folder / (PACKAGE + "." + VERSION + ".nupkg.sha512")
    if (archive.is_symlink() or not archive.is_file()
            or not 0 < archive.stat().st_size <= MAX_ARCHIVE):
        raise AuditError("missing, symlinked or oversized SDK .nupkg")
    cached_hash = _sha512_text(_read(hashfile, 512).decode("ascii").strip(),
                               "local cache")
    assets_hash = _sha512_text(row["nugetSha512Metadata"], "project assets")
    digest = hashlib.sha512()
    with archive.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    if cached_hash != assets_hash or digest.digest() != assets_hash:
        # Three distinct hashes are public exact-package bytes/metadata only.
        # Diagnose which source disagrees WITHOUT allowing an unsigned match
        # or silently discarding the restore's originally selected digest.
        raise AuditError("NUGET_SHA512_TRIAD_MISMATCH"
                         + " cache=" + cached_hash.hex()[:24]
                         + " assets=" + assets_hash.hex()[:24]
                         + " archive=" + digest.digest().hex()[:24])
    listing = _archive_entries(archive, row["localNuspecSha256"])
    return {
        "schemaVersion": 1,
        "status": "PACKAGE_BYTES_VERIFIED_LICENSE_BLOCKED",
        "scope": "exact local NuGet BuildTools 10.0.26100.4654 ZIP vs restore+cache SHA512 only",
        "purl": PURL,
        "nupkgSha512Hex": digest.hexdigest(),
        "nupkgByteSize": archive.stat().st_size,
        "packageHashMatchesAssetsAndCache": True,
        "nuspecHashMatchesRestore": True,
        **listing,
        "directNuspecLicense": "MISSING",
        "legacySupplierLicenseUrl": LEGACY_URL,
        "exactVersionLicenseTermsVerified": False,
        "redistributionFileListVerified": False,
        "redistributableAssetRightsVerified": False,
        "publisherSignatureVerified": False,
        "archiveSignatureVerified": False,
        "windowsNativePackageVerified": False,
        "noticeClosure": "NOT_VERIFIED",
        "sbomComplete": False,
        "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--restore-report", required=True, type=Path)
    p.add_argument("--packages", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        payload = _read(args.restore_report, MAX_INPUT)
        result = audit(json.loads(payload.decode("utf-8")), args.packages)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (AuditError, OSError, UnicodeError, ValueError, TypeError) as exc:
        print("BLOCKED: BuildTools exact NuGet redistributable review: " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"],
                      "nupkgByteSize": result["nupkgByteSize"],
                      "redistCandidateFiles": len(result["redistFilenameCandidates"]),
                      "exactVersionLicenseTermsVerified": False,
                      "releaseApproved": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
