#!/usr/bin/env python3
"""One exact resolved Guava ListenableFuture 1.0 JAR/Apache source review.

The 1.0 JAR must contain ListenableFuture.class. The separate 9999.0-empty
artifact is intentionally NOT interchangeable. Neither source legal labels nor
byte equality clear Android NOTICE, parent POM, signature or release gates.
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
from urllib import request, error
import xml.etree.ElementTree as ET
import zipfile

PURL = "pkg:maven/com.google.guava/listenablefuture@1.0"
COORDINATE = "com.google.guava:listenablefuture:1.0"
TAG_COMMIT = "a35bfd9ea855539354b783ee74839e384f7af98a"  # google/guava v27.0
TAG_MODULE_TREE = "2d264994055c7f26a8e85dbdc31f979a3ccb8445"
TAG_COPYING_BLOB = "d645695673349e3947e8e5ae42332d0ac3164cd7"
MAVEN_BASE = "https://repo.maven.apache.org/maven2/com/google/guava/listenablefuture/1.0/"
POM_URL = MAVEN_BASE + "listenablefuture-1.0.pom"
JAR_URL = MAVEN_BASE + "listenablefuture-1.0.jar"
LICENSE_URL = "https://raw.githubusercontent.com/google/guava/" + TAG_COMMIT + "/COPYING"
TREE_URL = "https://api.github.com/repos/google/guava/git/trees/" + TAG_MODULE_TREE + "?recursive=1"
LIMITS = {POM_URL: 65536, JAR_URL: 1500000, LICENSE_URL: 20000, TREE_URL: 65536}
# Filled only using complete official Maven bytes observed in real hosted CI.
POM_SHA256 = "53873caf26bc1ed8a567ea6c939ab2aaa3f47a5e32d5cade95ddf5080d23238a"
JAR_SHA256 = "e4ad7607e5c0477c6f890ef26a49cb8d1bb4dffb650bab4502afee64644e3069"


class ProbeError(ValueError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProbeError("upstream HTTPS redirect disallowed")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def official_fetch(url: str) -> bytes:
    if url not in LIMITS:
        raise ProbeError("unapproved source endpoint")
    headers = {"User-Agent": "Embasic-E-Scanner-Guava-ListenableFuture100-SourceGate/1",
               "Accept": "application/vnd.github+json" if url == TREE_URL else "application/octet-stream"}
    if url == TREE_URL:
        token = os.environ.get("E_SCANNER_GITHUB_TREE_READ_TOKEN", "")
        if token:
            if len(token) > 4096 or not token.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise ProbeError("malformed ephemeral GitHub token")
            headers["Authorization"] = "Bearer " + token
    req = request.Request(url, headers=headers)
    try:
        with request.build_opener(NoRedirect).open(req, timeout=20) as response:
            if response.status != 200:
                raise ProbeError("unexpected source HTTP status for " + url)
            content = response.read(LIMITS[url] + 1)
    except error.HTTPError as exc:
        raise ProbeError("official source HTTP " + str(exc.code) + " for " + url) from exc
    except (error.URLError, OSError, TimeoutError) as exc:
        raise ProbeError("official source HTTPS unavailable for " + url) from exc
    if not 0 < len(content) <= LIMITS[url]:
        raise ProbeError("empty or oversized upstream data")
    return content


def nodes(parent: ET.Element, field: str) -> list[ET.Element]:
    return [x for x in parent if x.tag.rsplit("}", 1)[-1] == field]


def unique_text(parent: ET.Element, field: str) -> str:
    found = nodes(parent, field)
    if len(found) != 1 or not (found[0].text or "").strip():
        raise ProbeError("missing or duplicated Maven " + field)
    return (found[0].text or "").strip()


def validate_pom(raw: bytes) -> dict:
    if not 0 < len(raw) <= LIMITS[POM_URL] or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ProbeError("untrusted POM entity or size")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ProbeError("malformed official Maven POM") from exc
    if root.tag.rsplit("}", 1)[-1] != "project":
        raise ProbeError("invalid Maven POM project")
    parent = nodes(root, "parent")
    if len(parent) > 1:
        raise ProbeError("ambiguous Maven parent")
    group_nodes = nodes(root, "groupId")
    if len(group_nodes) > 1:
        raise ProbeError("ambiguous Maven groupId")
    group = unique_text(root, "groupId") if group_nodes else (
        unique_text(parent[0], "groupId") if parent else "")
    artifact = unique_text(root, "artifactId")
    version = unique_text(root, "version")
    if (group, artifact, version) != ("com.google.guava", "listenablefuture", "1.0"):
        raise ProbeError("official Maven POM selected coordinates mismatch")
    license_groups = nodes(root, "licenses")
    if len(license_groups) > 1:
        raise ProbeError("ambiguous direct Maven license declarations")
    declared = []
    if license_groups:
        for item in nodes(license_groups[0], "license"):
            declared.append(unique_text(item, "name"))
    if declared and not all("apache" in name.lower() and "2.0" in name for name in declared):
        raise ProbeError("unexpected direct Maven license claim")
    descr = nodes(root, "description")
    description = (descr[0].text or "").strip() if len(descr) == 1 else ""
    return {"groupId": group, "artifactId": artifact, "version": version,
            "directLicenseClaims": declared,
            "inheritedParentLicenseReview": "NOT_VERIFIED",
            "descriptionMentionsRealOneAndEmpty9999": (
                "ListenableFuture" in description and "9999" in description)}


def validate_jar(raw: bytes) -> dict:
    if not 0 < len(raw) <= LIMITS[JAR_URL] or not zipfile.is_zipfile(BytesIO(raw)):
        raise ProbeError("invalid official Maven JAR")
    with zipfile.ZipFile(BytesIO(raw)) as jar:
        entries = jar.infolist()
        if not 1 <= len(entries) <= 1500 or sum(e.file_size for e in entries) > 10000000:
            raise ProbeError("JAR member limits exceeded")
        names = [e.filename for e in entries]
        if len(names) != len(set(names)):
            raise ProbeError("duplicate JAR member")
        for e in entries:
            if (e.filename.startswith("/") or "\\" in e.filename or ".." in e.filename.split("/")
                    or ((e.external_attr >> 16) & 0o170000) == 0o120000):
                raise ProbeError("unsafe JAR member")
        if jar.testzip() is not None:
            raise ProbeError("JAR CRC corrupt")
        core = "com/google/common/util/concurrent/ListenableFuture.class"
        if core not in names:
            raise ProbeError("wrong empty/placeholder JAR: ListenableFuture.class absent")
        classes = sorted(n for n in names if n.endswith(".class"))
        if classes != [core]:
            raise ProbeError("unexpected Java class inventory in ListenableFuture JAR")
        legal = sorted(n for n in names
                       if n.rsplit("/", 1)[-1].lower() in
                       ("notice", "notice.txt", "notice.md", "license", "license.txt",
                        "license.md", "copying"))
        return {"classNames": classes, "embeddedLegalFilenames": legal, "fileCount": len(entries)}


def validate_tree(data: bytes) -> dict:
    try:
        source = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ProbeError("invalid upstream tagged source JSON") from exc
    if (not isinstance(source, dict) or source.get("sha") != TAG_MODULE_TREE
            or source.get("truncated") is not False):
        raise ProbeError("untrusted Git release module tree")
    entries = source.get("tree")
    if not isinstance(entries, list) or not 8 <= len(entries) <= 40:
        raise ProbeError("unbounded source module entries")
    files = [row.get("path") for row in entries
             if isinstance(row, dict) and row.get("type") == "blob"]
    java = "src/com/google/common/util/concurrent/ListenableFuture.java"
    if files.count(java) != 1 or files.count("pom.xml") != 1:
        raise ProbeError("source tag module does not contain target Java source/POM")
    if any(p.rsplit("/", 1)[-1].lower() in ("notice", "notice.txt", "notice.md") for p in files):
        raise ProbeError("tag module NOTICE exists: review exact text before reporting absence")
    return {"tagName": "v27.0", "tagCommit": TAG_COMMIT, "treeSha": TAG_MODULE_TREE,
            "moduleEntries": len(entries), "moduleNoticeFilename": "ABSENT_IN_TAG_MODULE_ONLY",
            "sourceToPublishedJarReproducibility": "NOT_VERIFIED"}


def audit(cache: Path, runtime: Path, testing: Path, get=official_fetch) -> dict:
    selected = {}
    match = re.compile(r"(?<![A-Za-z0-9_.-])com\.google\.guava:listenablefuture:1\.0(?![A-Za-z0-9_.-])")
    for key, file in (("debugRuntimeClasspath", runtime), ("debugUnitTestRuntimeClasspath", testing)):
        if file.is_symlink() or not file.is_file() or not 0 < file.stat().st_size <= 2000000:
            raise ProbeError("unsafe or absent Gradle dependency report")
        content = file.read_text(encoding="utf-8")
        if "BUILD SUCCESSFUL" not in content:
            raise ProbeError("unverified Gradle dependency resolution")
        selected[key] = bool(match.search(content))
    if not any(selected.values()):
        raise ProbeError("Maven artifact 1.0 not actually resolved by selected configurations")
    parent = cache / "com.google.guava" / "listenablefuture" / "1.0"
    for p in (cache, cache / "com.google.guava", cache / "com.google.guava" / "listenablefuture", parent):
        if p.is_symlink():
            raise ProbeError("symlinked Gradle cache parent")
    found = sorted(parent.glob("*/listenablefuture-1.0.jar"))
    if len(found) != 1 or found[0].is_symlink() or found[0].parent.is_symlink():
        raise ProbeError("missing or ambiguous Gradle-selected exact JAR")
    if not 0 < found[0].stat().st_size <= LIMITS[JAR_URL]:
        raise ProbeError("Gradle JAR size exceeds limit")
    local = found[0].read_bytes()
    official = {url: get(url) for url in (POM_URL, JAR_URL, LICENSE_URL, TREE_URL)}
    for url, data in official.items():
        if not isinstance(data, bytes) or not 0 < len(data) <= LIMITS[url]:
            raise ProbeError("official source returned invalid size/data")
    pom, jar, licence, tree = (official[u] for u in (POM_URL, JAR_URL, LICENSE_URL, TREE_URL))
    if POM_SHA256 and sha256(pom) != POM_SHA256:
        raise ProbeError("pinned official Maven POM SHA-256 changed")
    if JAR_SHA256 and sha256(jar) != JAR_SHA256:
        raise ProbeError("pinned official Maven JAR SHA-256 changed")
    pom_details = validate_pom(pom)
    jar_details = validate_jar(jar)
    if git_blob(licence) != TAG_COPYING_BLOB or b"Apache License" not in licence or b"Version 2.0" not in licence:
        raise ProbeError("pinned Guava v27.0 COPYING source text mismatch")
    src = validate_tree(tree)
    if len(local) != len(jar) or sha256(local) != sha256(jar):
        raise ProbeError("exact Gradle-selected JAR differs from official Maven Central bytes")
    return {
        "schemaVersion": 1, "purl": PURL, "status": "EXACT_MAVEN_GRADLE_JAR_BYTES_MATCH_LEGAL_OPEN",
        "gradleSelectedConfigurations": selected,
        "officialPOM": dict(pom_details, url=POM_URL, byteSize=len(pom), sha256=sha256(pom)),
        "officialJAR": dict(jar_details, url=JAR_URL, byteSize=len(jar), sha256=sha256(jar),
                            gradleByteParity=True),
        "upstreamCopying": {"url": LICENSE_URL, "gitBlobSha1": git_blob(licence),
                            "sha256": sha256(licence), "byteSize": len(licence)},
        "upstreamTagModule": src, "hashPinsVerified": bool(POM_SHA256 and JAR_SHA256),
        "full85AndroidNoticeRowsStillOpen": True, "independent42GradlePomGapsOpen": True,
        "noticeClosure": "NOT_VERIFIED", "licenseClosure": "NOT_VERIFIED",
        "publisherSignatureVerified": False, "sourceToBinaryVerified": False,
        "apkPackagingVerified": False, "sbomComplete": False, "releaseApproved": False
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    for k in ("cache", "runtime", "test", "output"):
        parser.add_argument("--" + k, type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(args.cache, args.runtime, args.test)
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        for label, value in (
            ("GUAVA100_OFFICIAL_POM_SHA256", report["officialPOM"]["sha256"]),
            ("GUAVA100_OFFICIAL_JAR_SHA256", report["officialJAR"]["sha256"]),
            ("GUAVA100_TAGGED_COPYING_SHA256", report["upstreamCopying"]["sha256"]),
            ("GUAVA100_OFFICIAL_JAR_BYTES", report["officialJAR"]["byteSize"]),
            ("GUAVA100_JAR_CLASSES", report["officialJAR"]["classNames"]),
            ("GUAVA100_JAR_LEGAL_FILES", report["officialJAR"]["embeddedLegalFilenames"]),
            ("GUAVA100_GRADLE_BYTE_PARITY", report["officialJAR"]["gradleByteParity"]),
            ("GUAVA100_LEGAL_CLOSURE", report["licenseClosure"])):
            print(label, value)
        return 0
    except (ProbeError, OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        args.output.write_text(json.dumps({
            "purl": PURL, "status": "BLOCKED_SOURCE_NOT_VERIFIED", "blocker": str(exc),
            "full85AndroidNoticeRowsStillOpen": True, "independent42GradlePomGapsOpen": True,
            "noticeClosure": "NOT_VERIFIED", "licenseClosure": "NOT_VERIFIED",
            "releaseApproved": False
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("BLOCKED Guava ListenableFuture source review:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
