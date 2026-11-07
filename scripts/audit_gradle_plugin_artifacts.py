#!/usr/bin/env python3
"""Partial, source-bounded Gradle build-tool artifact + POM metadata inventory.

Input: actual root/app buildEnvironment graph JSON from the PUBLIC CI. For each
selected Maven purl, enumerate and SHA-256 hash locally cached JAR/POM/module/AAR
bytes; extract untrusted *supplier-declared* license names from POM files.

This is NOT a complete SBOM, upstream signature/provenance proof, license
approval, release binary inventory or an Android application runtime audit.
Missing artifacts are reported as gaps, never silently considered verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

PURL = re.compile(r"pkg:maven/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)\Z")
CACHE_DIGEST = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_EXT = frozenset({".jar", ".pom", ".module", ".aar"})
MAX_INPUT = 3_000_000
MAX_METADATA = 1_000_000
MAX_FILE = 128 * 1024 * 1024
MAX_COUNT = 512


class AuditError(ValueError):
    pass


def _file_bytes(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise AuditError("untrusted, unavailable or oversized evidence file")
    return path.read_bytes()


def _safe_segment(value: str) -> bool:
    return (value not in ("", ".", "..")
            and ".." not in value and not value.startswith(".")
            and "/" not in value and "\\" not in value)


def _licenses(raw: bytes) -> list[dict]:
    """Supplier metadata is untrusted and is NEVER a license approval."""
    if len(raw) > MAX_METADATA:
        return [{"name": "UNREADABLE_OVERSIZE_POM", "url": ""}]
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return [{"name": "UNREADABLE_POM", "url": ""}]
    names = []
    for lic in root.findall(".//{*}licenses/{*}license"):
        name = (lic.findtext("{*}name") or "").strip()[:256]
        url = (lic.findtext("{*}url") or "").strip()[:512]
        if name:
            names.append({"name": name, "url": url})
    return sorted(names, key=lambda x: (x["name"], x["url"]))


def _pom_parent(raw: bytes) -> str | None:
    """Unverified, explicitly unresolved POM parent reference; no license inheritance."""
    if len(raw) > MAX_METADATA:
        return None
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    parent = root.find("{*}parent")
    if parent is None:
        return None
    coordinates = [(parent.findtext("{*}" + tag) or "").strip()
                   for tag in ("groupId", "artifactId", "version")]
    if all(coordinates) and all(_safe_segment(value) for value in coordinates):
        return ":".join(coordinates)[:512]
    return None


def _parent_chain(first: str, cache: Path) -> list[dict]:
    """Bounded cached POM ancestry hints, NOT inherited license approval.

    Do not contact a repository, synthesize parent licenses, or mark supplier
    metadata as verified. Absent parent POM files remain explicit gaps.
    """
    trail: list[dict] = []
    seen: set[str] = set()
    current: str | None = first
    for _ in range(5):
        if not current:
            return trail
        if current in seen:
            raise AuditError("cyclic parent POM chain")
        seen.add(current)
        fields = current.split(":")
        if len(fields) != 3 or any(not _safe_segment(x) for x in fields):
            raise AuditError("unsafe parent POM coordinate")
        group, artifact, version = fields
        folder = cache / group / artifact / version
        record = {"coordinate": current, "status": "PARENT_POM_NOT_CACHED",
                  "sha256": None, "unverifiedLicenseNames": [],
                  "licenseApproved": False}
        if folder.is_symlink():
            raise AuditError("symlinked parent POM directory")
        if not folder.is_dir():
            trail.append(record)
            return trail
        # Parent POMs are metadata only; no implicit dependency or license
        # injection into selected Gradle buildEnvironment graph.
        found = []
        children = list(folder.iterdir())
        if len(children) > MAX_COUNT:
            raise AuditError("unbounded parent cache")
        for entry in children:
            if entry.is_symlink():
                raise AuditError("symlinked parent POM cache entry")
            if entry.is_dir() and CACHE_DIGEST.fullmatch(entry.name):
                file = entry / (artifact + "-" + version + ".pom")
                if file.is_symlink():
                    raise AuditError("symlinked parent POM")
                if file.is_file():
                    found.append(file)
        if len(found) > 1:
            raise AuditError("ambiguous parent POM cache bytes")
        if not found:
            trail.append(record)
            return trail
        raw = _file_bytes(found[0], MAX_METADATA)
        record["sha256"] = hashlib.sha256(raw).hexdigest()
        lic = _licenses(raw)
        record["unverifiedLicenseNames"] = sorted(
            {x["name"] for x in lic if not x["name"].startswith("UNREADABLE_")})
        record["status"] = ("PARENT_POM_METADATA_ONLY" if
                            not any(x["name"].startswith("UNREADABLE_") for x in lic)
                            else "UNREADABLE_PARENT_POM")
        trail.append(record)
        if record["status"] == "UNREADABLE_PARENT_POM":
            return trail
        current = _pom_parent(raw)
    if current:
        trail.append({"coordinate": current, "status": "DEPTH_LIMIT_NOT_VERIFIED",
                      "sha256": None, "unverifiedLicenseNames": [],
                      "licenseApproved": False})
    return trail


def audit(graph: dict, cache: Path) -> dict:
    if (graph.get("status") != "PASS"
            or graph.get("inventoryCompleteness") != "PARTIAL"
            or graph.get("releaseApproved") is not False
            or graph.get("artifactHashesCovered") is not False
            or graph.get("pluginBinaryLicensesVerified") is not False):
        raise AuditError("upstream plugin graph scope is untrusted")
    root = graph.get("root")
    app = graph.get("app")
    if not isinstance(root, list) or not isinstance(app, list):
        raise AuditError("missing root/app scope")
    if (graph.get("moduleCounts") != {"root": len(root), "app": len(app)}
            or not root or len(root) + len(app) > MAX_COUNT):
        raise AuditError("missing or tampered scope counts")
    if cache.is_symlink() or not cache.is_dir():
        raise AuditError("unsafe Gradle cache root")

    modules: dict[str, dict] = {}
    for scope, elements in (("root", root), ("app", app)):
        for element in elements:
            if (not isinstance(element, dict)
                    or element.get("licenseApproved") is not False
                    or element.get("binaryProvenance") != "NOT_VERIFIED"):
                raise AuditError("graph incorrectly asserts trusted provenance")
            purl = element.get("purl", "")
            match = PURL.fullmatch(purl) if isinstance(purl, str) else None
            if match is None or any(not _safe_segment(x) for x in match.groups()):
                raise AuditError("unsafe selected Maven purl")
            record = modules.setdefault(purl, {
                "purl": purl, "scopes": [], "cachedFiles": [],
                "pomDeclaredLicenses": [], "cacheStatus": "NOT_CHECKED",
                "pomFilesSeen": 0, "unresolvedPomParents": [],
                "licenseMetadataState": "NOT_CHECKED",
            })
            if scope in record["scopes"]:
                raise AuditError("duplicate selected Maven purl in one scope")
            record["scopes"].append(scope)
    expected = {
        "pkg:maven/com.android.tools.build/gradle@8.13.2",
        "pkg:maven/org.jetbrains.kotlin/kotlin-gradle-plugin@2.3.21",
    }
    if not expected.issubset(modules):
        raise AuditError("mandatory pinned Android/Kotlin plugin modules missing")

    totals = {"modules": len(modules), "withLocalBytes": 0,
              "withoutLocalBytes": 0, "hashedFiles": 0,
              "unreadablePom": 0, "pomWithLicenseNames": 0,
              "pomWithoutDirectLicenseName": 0, "pomNotCached": 0,
              "pomHasUnresolvedParent": 0}
    for purl, record in sorted(modules.items()):
        group, name, version = PURL.fullmatch(purl).groups()
        base = cache / group / name / version
        if base.is_symlink():
            raise AuditError("symlinked selected module cache directory")
        if not base.is_dir():
            record["cacheStatus"] = "NO_LOCAL_EVIDENCE"
            record["licenseMetadataState"] = "POM_NOT_CACHED"
            totals["pomNotCached"] += 1
            totals["withoutLocalBytes"] += 1
            continue
        hashes = sorted(base.iterdir())
        if len(hashes) > MAX_COUNT:
            raise AuditError("excessive cache digest directories")
        found: list[dict] = []
        license_set: set[tuple[str, str]] = set()
        unreadable = False
        pom_files = 0
        parents: set[str] = set()
        for sub in hashes:
            if sub.is_symlink():
                raise AuditError("symlinked Gradle cache digest")
            if not sub.is_dir() or not CACHE_DIGEST.fullmatch(sub.name):
                continue
            children = sorted(sub.iterdir())
            if len(children) > MAX_COUNT:
                raise AuditError("excessive cache artifacts")
            for file in children:
                if file.suffix.lower() not in ALLOWED_EXT:
                    continue
                if file.is_symlink() or not file.is_file():
                    raise AuditError("symlinked or unsafe cached Maven artifact")
                if not file.name.startswith(name + "-" + version + "."):
                    continue
                size = file.stat().st_size
                if size <= 0 or size > MAX_FILE:
                    record["cacheStatus"] = "OVERSIZED_OR_EMPTY_ARTIFACT"
                    continue
                digest = hashlib.sha256()
                with file.open("rb") as reader:
                    for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                        digest.update(chunk)
                found.append({"filename": file.name, "byteSize": size,
                              "sha256": digest.hexdigest(),
                              "sourceVerification": "LOCAL_BYTES_ONLY"})
                if file.suffix.lower() == ".pom":
                    pom_files += 1
                    content = _file_bytes(file, MAX_FILE)
                    parent = _pom_parent(content)
                    if parent:
                        parents.add(parent)
                    for lic in _licenses(content):
                        if lic["name"].startswith("UNREADABLE_"):
                            unreadable = True
                        else:
                            license_set.add((lic["name"], lic["url"]))
        record["cachedFiles"] = sorted(found, key=lambda x: (x["filename"], x["sha256"]))
        record["pomDeclaredLicenses"] = [
            {"name": name, "url": url, "evidence": "UNVERIFIED_SUPPLIER_POM"}
            for name, url in sorted(license_set)
        ]
        if found:
            record["cacheStatus"] = "LOCAL_BYTES_HASHED"
            totals["withLocalBytes"] += 1
        else:
            if record["cacheStatus"] != "OVERSIZED_OR_EMPTY_ARTIFACT":
                record["cacheStatus"] = "NO_LOCAL_EVIDENCE"
            totals["withoutLocalBytes"] += 1
        totals["hashedFiles"] += len(found)
        record["pomFilesSeen"] = pom_files
        record["unresolvedPomParents"] = sorted(parents)
        if license_set:
            record["licenseMetadataState"] = "DIRECT_POM_LICENSE_NAME"
            totals["pomWithLicenseNames"] += 1
        elif unreadable:
            record["licenseMetadataState"] = "UNREADABLE_POM"
        elif pom_files:
            record["licenseMetadataState"] = "POM_WITHOUT_DIRECT_LICENSE_NAME"
            totals["pomWithoutDirectLicenseName"] += 1
        else:
            record["licenseMetadataState"] = "POM_NOT_CACHED"
            totals["pomNotCached"] += 1
        if parents:
            totals["pomHasUnresolvedParent"] += 1
        if unreadable:
            totals["unreadablePom"] += 1
        record["parentPomEvidence"] = (
            [_parent_chain(parent, cache) for parent in sorted(parents)]
            if not license_set else []
        )

    if totals["withLocalBytes"] == 0 or totals["hashedFiles"] == 0:
        raise AuditError("no selected plugin artifact bytes were verified")
    return {
        "schemaVersion": 1,
        "scope": "Android Gradle root/app buildEnvironment LOCAL cache evidence only",
        "status": "PASS_WITH_GAPS",
        "modules": [modules[k] for k in sorted(modules)],
        "counts": totals,
        "missingDirectLicenseEvidence": [
            {"purl": record["purl"], "reason": record["licenseMetadataState"],
             "unresolvedPomParents": record["unresolvedPomParents"]}
            for record in (modules[key] for key in sorted(modules))
            if not record["pomDeclaredLicenses"]
        ],
        "parentLicenseInheritanceVerified": False,
        "originVerified": False,
        "licenseApproval": "NOT_VERIFIED",
        "inventoryCompleteness": "PARTIAL",
        "noticeClosure": "NOT_VERIFIED",
        "sbomComplete": False,
        "releaseApproved": False,
    }


def check_partial_notice(result: dict, notice: str) -> None:
    """Fail closed on stale/relabelled snapshot numbers, never approve licenses."""
    if ("NOT a complete SBOM" not in notice
            or "UNVERIFIED_SUPPLIER_POM" not in notice
            or "releaseApproved=false" not in notice):
        raise AuditError("missing partial NOTICE no-release boundary")
    counts = result["counts"]
    if len(result["missingDirectLicenseEvidence"]) != (
            counts["modules"] - counts["pomWithLicenseNames"]):
        raise AuditError("POM-license gap list disagrees with resolved graph")
    if (counts["pomWithoutDirectLicenseName"] + counts["pomNotCached"]
            + counts["unreadablePom"] != len(result["missingDirectLicenseEvidence"])):
        raise AuditError("POM-license gap reason totals are inconsistent")
    expected = {
        "pluginModules": counts["modules"],
        "pluginLicenseNameMetadata": counts["pomWithLicenseNames"],
        "pluginMissingLicenseMetadata":
            counts["modules"] - counts["pomWithLicenseNames"],
        "pluginCachedFileHashes": counts["hashedFiles"],
    }
    for name, count in expected.items():
        marker = f"- {name}: {count}"
        if notice.splitlines().count(marker) != 1:
            raise AuditError("stale or duplicate partial plugin NOTICE counter: " + name)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--graph", type=Path, required=True)
    p.add_argument("--cache", type=Path, required=True)
    p.add_argument("--notice", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        raw = _file_bytes(args.graph, MAX_INPUT)
        graph = json.loads(raw)
        result = audit(graph, args.cache)
        check_partial_notice(result, _file_bytes(args.notice, MAX_INPUT).decode("utf-8"))
        result["partialNoticeCheck"] = "PASS"
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (AuditError, OSError, UnicodeError, ValueError, TypeError) as exc:
        print("BLOCKED: Gradle plugin cached artifact audit: " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({
        "status": result["status"], "counts": result["counts"],
        "missingDirectLicenseEvidence": result["missingDirectLicenseEvidence"],
        "parentLicenseInheritanceVerified": False,
        "originVerified": False, "licenseApproval": "NOT_VERIFIED",
        "sbomComplete": False, "releaseApproved": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
