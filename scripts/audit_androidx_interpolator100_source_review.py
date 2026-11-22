#!/usr/bin/env python3
"""Single resolved AndroidX Interpolator 1.0.0 Google Maven AAR provenance gate.

The upstream pre-deletion source snapshot is NOT the original 2018 release tag.
Official binary/cache equality and supplier legal labels do not grant release rights.
"""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import sys
from urllib import error, request
import xml.etree.ElementTree as ET
import zipfile

PURL = "pkg:maven/androidx.interpolator/interpolator@1.0.0"
COORDINATE = "androidx.interpolator:interpolator:1.0.0"
SOURCE_COMMIT = "15d3a78f3e1976f7dd6ba687cba586d79c9d16e5"
SOURCE_MODULE_TREE = "2eea69702006ce32a9832cc5f8f1b7fe7b7143c6"
SOURCE_LICENSE_BLOB = "e454a52586f29b8ce8a6799163eac1f875e9ac01"
MAVEN = "https://dl.google.com/dl/android/maven2/androidx/interpolator/interpolator/1.0.0/"
POM_URL = MAVEN + "interpolator-1.0.0.pom"
AAR_URL = MAVEN + "interpolator-1.0.0.aar"
LICENSE_URL = "https://raw.githubusercontent.com/androidx/androidx/" + SOURCE_COMMIT + "/LICENSE.txt"
SOURCE_TREE_URL = "https://api.github.com/repos/androidx/androidx/git/trees/" + SOURCE_MODULE_TREE + "?recursive=1"
LIMITS = {POM_URL: 65536, AAR_URL: 2000000, LICENSE_URL: 20000, SOURCE_TREE_URL: 250000}
# Pin only after the first full official Google Maven & real Gradle CI match.
POM_SHA256 = ""
AAR_SHA256 = ""


class AuditError(ValueError):
    pass


class RefuseRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("upstream redirect forbidden")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def origin(url: str) -> str:
    return "GOOGLE_MAVEN_POM" if url == POM_URL else "GOOGLE_MAVEN_AAR" if url == AAR_URL else (
        "UPSTREAM_LICENSE" if url == LICENSE_URL else "UPSTREAM_MODULE_TREE")


def official_fetch(url: str) -> bytes:
    if url not in LIMITS:
        raise AuditError("unallowlisted source URL")
    headers = {
        "Accept": "application/vnd.github+json" if url == SOURCE_TREE_URL else "application/octet-stream",
        "User-Agent": "Embasic-E-Scanner-AndroidX-Interpolator100-ExactProbe/1",
    }
    # Ephemeral GitHub read-only token exclusively for the pinned API tree URL.
    if url == SOURCE_TREE_URL:
        token = os.environ.get("E_SCANNER_GITHUB_TREE_READ_TOKEN", "")
        if token:
            if len(token) > 4096 or not token.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise AuditError("invalid restricted GitHub token")
            headers["Authorization"] = "Bearer " + token
    req = request.Request(url, headers=headers)
    try:
        with request.build_opener(RefuseRedirect).open(req, timeout=20) as response:
            if response.status != 200:
                raise AuditError(origin(url) + " unexpected upstream status")
            data = response.read(LIMITS[url] + 1)
    except error.HTTPError as exc:
        raise AuditError(origin(url) + " HTTP " + str(exc.code)) from exc
    except (error.URLError, OSError, TimeoutError) as exc:
        raise AuditError(origin(url) + " HTTPS unavailable") from exc
    if not 0 < len(data) <= LIMITS[url]:
        raise AuditError(origin(url) + " size limit")
    return data


def direct_field(node: ET.Element, name: str) -> str:
    matches = [(x.text or "").strip() for x in node if x.tag.rsplit("}", 1)[-1] == name]
    if len(matches) != 1 or not matches[0]:
        raise AuditError("ambiguous official POM field " + name)
    return matches[0]


def validate_pom(pom: bytes) -> str:
    if not 0 < len(pom) <= LIMITS[POM_URL] or b"<!DOCTYPE" in pom.upper() or b"<!ENTITY" in pom.upper():
        raise AuditError("untrusted Google POM XML")
    try:
        root = ET.fromstring(pom)
    except ET.ParseError as exc:
        raise AuditError("malformed Google POM") from exc
    if root.tag.rsplit("}", 1)[-1] != "project":
        raise AuditError("not a Maven POM root")
    for name, expected in (("groupId", "androidx.interpolator"), ("artifactId", "interpolator"),
                           ("version", "1.0.0")):
        if direct_field(root, name) != expected:
            raise AuditError("wrong official POM coordinate")
    license_groups = [x for x in root if x.tag.rsplit("}", 1)[-1] == "licenses"]
    if len(license_groups) != 1:
        raise AuditError("no unambiguous direct POM licence claim")
    names = [direct_field(x, "name") for x in license_groups[0]
             if x.tag.rsplit("}", 1)[-1] == "license"]
    if len(names) != 1 or "apache" not in names[0].lower() or "2.0" not in names[0]:
        raise AuditError("official POM licence claim unexpected")
    return names[0]


def check_zip(raw: bytes, cap: int, max_members: int) -> zipfile.ZipFile:
    if not 0 < len(raw) <= cap or not zipfile.is_zipfile(BytesIO(raw)):
        raise AuditError("missing or oversized ZIP")
    zf = zipfile.ZipFile(BytesIO(raw))
    entries = zf.infolist()
    if len(entries) < 1 or len(entries) > max_members or sum(x.file_size for x in entries) > cap * 12:
        zf.close()
        raise AuditError("ZIP member bounds exceeded")
    names = [x.filename for x in entries]
    if len(set(names)) != len(names) or any(
        x.startswith("/") or ".." in x.split("/") or "\\" in x or
        ((x.external_attr >> 16) & 0o170000) == 0o120000
        for x in entries for _ in (0,) if isinstance(x, zipfile.ZipInfo)
    ):
        zf.close()
        raise AuditError("unsafe ZIP member")
    if zf.testzip() is not None:
        zf.close()
        raise AuditError("ZIP CRC failed")
    return zf


def validate_aar(raw: bytes) -> list[str]:
    with check_zip(raw, LIMITS[AAR_URL], 3000) as zf:
        names = [x.filename for x in zf.infolist()]
        if "classes.jar" not in names or "AndroidManifest.xml" not in names:
            raise AuditError("Android AAR required entries missing")
        inner = zf.read("classes.jar")
        embedded = sorted(x for x in names if x.rsplit("/", 1)[-1].lower() in
                          ("license", "license.txt", "license.md", "notice", "notice.txt", "notice.md"))
    with check_zip(inner, 1800000, 4000) as jars:
        if "androidx/interpolator/view/animation/FastOutSlowInInterpolator.class" not in jars.namelist():
            raise AuditError("interpolator class signature missing")
    return embedded


def validate_source_tree(data: bytes) -> int:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise AuditError("invalid pinned AndroidX tree") from exc
    if not isinstance(obj, dict) or obj.get("sha") != SOURCE_MODULE_TREE or obj.get("truncated") is not False:
        raise AuditError("changed or incomplete AndroidX tree")
    rows = obj.get("tree")
    if not isinstance(rows, list) or not 10 <= len(rows) <= 1000:
        raise AuditError("unbounded AndroidX module tree")
    files = [x["path"] for x in rows if isinstance(x, dict)
             and x.get("type") == "blob" and isinstance(x.get("path"), str)]
    expected = ("api/1.0.0.txt",
                "src/main/java/androidx/interpolator/view/animation/FastOutSlowInInterpolator.java")
    if any(files.count(name) != 1 for name in expected):
        raise AuditError("source snapshot lacks exact Interpolator API/class")
    # Absence in this module subtree is a narrow inventory result, not licence waiver.
    if any(x.rsplit("/", 1)[-1].lower() in ("notice", "notice.txt", "notice.md") for x in files):
        raise AuditError("upstream NOTICE needs exact-text review")
    return len(rows)


def audit(cache: Path, runtime: Path, testing: Path, get=official_fetch) -> dict:
    selected = {}
    pattern = re.compile(r"(?<![A-Za-z0-9_.-])androidx\.interpolator:interpolator:1\.0\.0(?![A-Za-z0-9_.-])")
    for key, path in (("debugRuntimeClasspath", runtime), ("debugUnitTestRuntimeClasspath", testing)):
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 2000000:
            raise AuditError("unsafe or absent Gradle dependency report")
        data = path.read_text(encoding="utf-8")
        if "BUILD SUCCESSFUL" not in data:
            raise AuditError("incomplete resolved Gradle report")
        selected[key] = bool(pattern.search(data))
    if not any(selected.values()):
        raise AuditError("this AAR is not actually selected in supplied Gradle reports")
    folder = cache / "androidx.interpolator" / "interpolator" / "1.0.0"
    for part in (cache, cache / "androidx.interpolator", cache / "androidx.interpolator" / "interpolator", folder):
        if part.is_symlink():
            raise AuditError("symlinked Gradle cache parent")
    hits = sorted(folder.glob("*/interpolator-1.0.0.aar"))
    if len(hits) != 1 or hits[0].parent.is_symlink() or hits[0].is_symlink():
        raise AuditError("exact AAR missing/ambiguous in Gradle module cache")
    if not 0 < hits[0].stat().st_size <= LIMITS[AAR_URL]:
        raise AuditError("Gradle cached AAR size invalid")
    local = hits[0].read_bytes()
    pom, aar, legal, tree = (get(url) for url in (POM_URL, AAR_URL, LICENSE_URL, SOURCE_TREE_URL))
    for url, raw in ((POM_URL, pom), (AAR_URL, aar), (LICENSE_URL, legal), (SOURCE_TREE_URL, tree)):
        if not 0 < len(raw) <= LIMITS[url]:
            raise AuditError("upstream source exceeds per-URL limits")
    if POM_SHA256 and digest(pom) != POM_SHA256:
        raise AuditError("pinned official Google POM hash drift")
    if AAR_SHA256 and digest(aar) != AAR_SHA256:
        raise AuditError("pinned official Google AAR hash drift")
    claim = validate_pom(pom)
    files = validate_aar(aar)
    if blob(legal) != SOURCE_LICENSE_BLOB or b"Apache License" not in legal or b"Version 2.0" not in legal:
        raise AuditError("pre-removal source LICENSE blob invalid")
    tree_size = validate_source_tree(tree)
    if len(local) != len(aar) or digest(local) != digest(aar):
        raise AuditError("Google Maven AAR does not match actual Gradle AAR bytes")
    return {
        "schemaVersion": 1, "purl": PURL, "status": "GOOGLE_MAVEN_GRADLE_AAR_BYTES_MATCH_LEGAL_OPEN",
        "resolvedGradleGraphs": selected,
        "officialPOM": {"url": POM_URL, "bytes": len(pom), "sha256": digest(pom),
                        "supplierLicenseClaim": claim},
        "officialAAR": {"url": AAR_URL, "bytes": len(aar), "sha256": digest(aar),
                        "gradleByteParity": True, "embeddedLegalFilenames": files},
        "upstreamLicense": {"url": LICENSE_URL, "sha256": digest(legal),
                            "gitBlobSha1": blob(legal), "bytes": len(legal)},
        "upstreamModule": {"sourceCommit": SOURCE_COMMIT, "treeSha": SOURCE_MODULE_TREE,
                           "treeUrl": SOURCE_TREE_URL, "fileEntries": tree_size,
                           "moduleNoticeFilenameStatus": "ABSENT_IN_PINNED_PREDELETION_TREE",
                           "release2018SourceIdentity": "NOT_VERIFIED"},
        "hashPinsVerified": bool(POM_SHA256 and AAR_SHA256),
        "publisherSignatureVerified": False, "apkPackagingVerified": False,
        "redistributionRightsVerified": False, "noticeClosure": "NOT_VERIFIED",
        "licenseClosure": "NOT_VERIFIED", "plugin42PomReviewOpen": True,
        "android85NoticeRowsOpen": True, "sbomComplete": False, "releaseApproved": False
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    for key in ("cache", "runtime", "test", "output"):
        ap.add_argument("--" + key, type=Path, required=True)
    args = ap.parse_args()
    try:
        report = audit(args.cache, args.runtime, args.test)
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print("INTERPOLATOR100_GOOGLE_POM_SHA256", report["officialPOM"]["sha256"])
        print("INTERPOLATOR100_GOOGLE_AAR_SHA256", report["officialAAR"]["sha256"])
        print("INTERPOLATOR100_SOURCE_LICENSE_SHA256", report["upstreamLicense"]["sha256"])
        print("INTERPOLATOR100_AAR_BYTES", report["officialAAR"]["bytes"])
        print("INTERPOLATOR100_EMBEDDED_LEGAL", report["officialAAR"]["embeddedLegalFilenames"])
        print("INTERPOLATOR100_GRADLE_BYTE_PARITY", report["officialAAR"]["gradleByteParity"])
        print("INTERPOLATOR100_NOTICE_CLOSURE", report["noticeClosure"])
        return 0
    except (AuditError, OSError, ValueError, UnicodeError, zipfile.BadZipFile) as exc:
        args.output.write_text(json.dumps({
            "purl": PURL, "status": "BLOCKED_SOURCE_NOT_VERIFIED", "blocker": str(exc),
            "licenseClosure": "NOT_VERIFIED", "noticeClosure": "NOT_VERIFIED",
            "releaseApproved": False, "plugin42PomReviewOpen": True,
            "android85NoticeRowsOpen": True
        }, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print("BLOCKED Interpolator100 source review:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
