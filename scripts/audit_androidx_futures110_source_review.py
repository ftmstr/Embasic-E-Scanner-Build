#!/usr/bin/env python3
"""One exact AndroidX concurrent-futures 1.1.0 Google Maven JAR legal-boundary probe.

A 2026 AndroidX module NOTICE is an independently verified later source snapshot,
NOT an automatically equivalent 2020 release NOTICE or a downstream waiver.
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

PURL = "pkg:maven/androidx.concurrent/concurrent-futures@1.1.0"
GAV = "androidx.concurrent:concurrent-futures:1.1.0"
SNAPSHOT_COMMIT = "4a63db244f62d809948bc2fb6676d62710c72609"
SNAPSHOT_MODULE_TREE = "222d6311a75d58ea87e086d1f2f40e7b328ee2a0"
SNAPSHOT_NOTICE_BLOB = "ff3ce54955d5b1300c096bd5a61a8129597a6122"
SNAPSHOT_LICENSE_BLOB = "e454a52586f29b8ce8a6799163eac1f875e9ac01"
BASE = "https://dl.google.com/dl/android/maven2/androidx/concurrent/concurrent-futures/1.1.0/"
POM_URL = BASE + "concurrent-futures-1.1.0.pom"
JAR_URL = BASE + "concurrent-futures-1.1.0.jar"
NOTICE_URL = ("https://raw.githubusercontent.com/androidx/androidx/" + SNAPSHOT_COMMIT
              + "/concurrent/concurrent-futures/src/main/resources/META-INF/NOTICE.txt")
LICENSE_URL = "https://raw.githubusercontent.com/androidx/androidx/" + SNAPSHOT_COMMIT + "/LICENSE.txt"
TREE_URL = ("https://api.github.com/repos/androidx/androidx/git/trees/" + SNAPSHOT_MODULE_TREE
            + "?recursive=1")
LIMITS = {POM_URL: 65536, JAR_URL: 2000000, NOTICE_URL: 40000,
          LICENSE_URL: 20000, TREE_URL: 250000}
# Fill from real Google Maven and Gradle-selected cache equality on first hosted CI.
POM_SHA256 = ""
JAR_SHA256 = ""


class AuditError(ValueError):
    pass


class RefuseRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("upstream redirect denied")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\x00" + data).hexdigest()


def fetch(url: str) -> bytes:
    if url not in LIMITS:
        raise AuditError("unallowlisted source URL")
    headers = {"User-Agent": "Embasic-E-Scanner-ConcurrentFutures110-SourceReview/1",
               "Accept": ("application/vnd.github+json" if url == TREE_URL
                          else "application/octet-stream")}
    if url == TREE_URL:
        token = os.environ.get("E_SCANNER_GITHUB_TREE_READ_TOKEN", "")
        if token:
            if len(token) > 4096 or not token.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise AuditError("invalid ephemeral GitHub read token")
            headers["Authorization"] = "Bearer " + token
    try:
        with request.build_opener(RefuseRedirect).open(
            request.Request(url, headers=headers), timeout=25
        ) as response:
            if response.status != 200:
                raise AuditError("non-200 upstream HTTP response")
            data = response.read(LIMITS[url] + 1)
    except error.HTTPError as exc:
        raise AuditError("official upstream HTTP " + str(exc.code) + ": " + url) from exc
    except (error.URLError, OSError, TimeoutError) as exc:
        raise AuditError("source fetch unavailable " + url) from exc
    if not 0 < len(data) <= LIMITS[url]:
        raise AuditError("empty or over-budget upstream response")
    return data


def children(el: ET.Element, tag: str) -> list[ET.Element]:
    return [c for c in el if c.tag.rsplit("}", 1)[-1] == tag]


def one(el: ET.Element, tag: str) -> str:
    found = children(el, tag)
    if len(found) != 1 or not (found[0].text or "").strip():
        raise AuditError("missing/duplicate Maven " + tag)
    return (found[0].text or "").strip()


def validate_pom(data: bytes) -> dict:
    if not 0 < len(data) <= LIMITS[POM_URL] or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise AuditError("malformed/unsafe Maven XML")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise AuditError("POM XML parse failure") from exc
    if root.tag.rsplit("}", 1)[-1] != "project":
        raise AuditError("wrong Maven project node")
    parent = children(root, "parent")
    if len(parent) > 1:
        raise AuditError("duplicate Maven parent")
    if children(root, "groupId"):
        group = one(root, "groupId")
    else:
        if not parent:
            raise AuditError("no Maven groupId")
        group = one(parent[0], "groupId")
    art = one(root, "artifactId")
    version = one(root, "version")
    if (group, art, version) != ("androidx.concurrent", "concurrent-futures", "1.1.0"):
        raise AuditError("exact AndroidX Maven GAV mismatch")
    licensing = children(root, "licenses")
    if len(licensing) > 1:
        raise AuditError("ambiguous POM licenses")
    claims = []
    if licensing:
        for entry in children(licensing[0], "license"):
            claims.append(one(entry, "name"))
    if claims and not all("apache" in l.lower() and "2.0" in l for l in claims):
        raise AuditError("unexpected Maven license claim; manual review needed")
    return {"coordinates": GAV, "directLicenseClaims": claims,
            "licenseAndNoticeCompleteness": "NOT_VERIFIED"}


def validate_jar(data: bytes) -> dict:
    if not 0 < len(data) <= LIMITS[JAR_URL] or not zipfile.is_zipfile(BytesIO(data)):
        raise AuditError("missing/corrupt official JAR")
    with zipfile.ZipFile(BytesIO(data)) as archive:
        entries = archive.infolist()
        if not 1 <= len(entries) <= 2000 or sum(e.file_size for e in entries) > 16000000:
            raise AuditError("JAR member budget exceeded")
        names = [x.filename for x in entries]
        if len(set(names)) != len(names):
            raise AuditError("duplicate JAR path")
        for entry in entries:
            if (entry.filename.startswith("/") or "\\" in entry.filename
                or ".." in entry.filename.split("/")
                or ((entry.external_attr >> 16) & 0o170000) == 0o120000):
                raise AuditError("JAR traversal or symlink")
        if archive.testzip() is not None:
            raise AuditError("corrupted JAR CRC")
        required = "androidx/concurrent/futures/CallbackToFutureAdapter.class"
        if required not in names:
            raise AuditError("published concurrent-futures JAR missing CallbackToFutureAdapter")
        classes = sorted(n for n in names if n.endswith(".class"))
        legal = sorted(n for n in names if n.rsplit("/", 1)[-1].lower() in
                       ("notice", "notice.txt", "notice.md", "license", "license.txt",
                        "license.md", "copying"))
        return {"classCount": len(classes), "callbackClassPresent": True,
                "embeddedLegalFilenames": legal, "entries": len(entries)}


def validate_tree(raw: bytes) -> dict:
    try:
        info = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise AuditError("malformed Git module tree") from exc
    if (not isinstance(info, dict) or info.get("sha") != SNAPSHOT_MODULE_TREE
            or info.get("truncated") is not False):
        raise AuditError("non-exact/truncated source module")
    entries = info.get("tree")
    if not isinstance(entries, list) or not 20 <= len(entries) <= 200:
        raise AuditError("source module tree size invalid")
    files = [x for x in entries if isinstance(x, dict) and x.get("type") == "blob"]
    paths = [x.get("path") for x in files]
    notice = "src/main/resources/META-INF/NOTICE.txt"
    callback = "src/main/java/androidx/concurrent/futures/CallbackToFutureAdapter.java"
    if paths.count(notice) != 1 or paths.count(callback) != 1 or paths.count("build.gradle") != 1:
        raise AuditError("pinned later source snapshot files absent")
    if next(x.get("sha") for x in files if x.get("path") == notice) != SNAPSHOT_NOTICE_BLOB:
        raise AuditError("pinned source NOTICE Git blob differs")
    return {"snapshotCommit": SNAPSHOT_COMMIT, "moduleTree": SNAPSHOT_MODULE_TREE,
            "entries": len(entries), "laterSourceNoticePresent": True,
            "release110NoticeCorrespondence": "NOT_VERIFIED",
            "sourceToReleasedJarReproducibility": "NOT_VERIFIED"}


def audit(cache: Path, runtime: Path, tests: Path, getter=fetch) -> dict:
    match = re.compile(r"(?<![A-Za-z0-9_.-])androidx\.concurrent:concurrent-futures:1\.1\.0(?![A-Za-z0-9_.-])")
    graphs = {}
    for label, path in (("debugRuntimeClasspath", runtime), ("debugUnitTestRuntimeClasspath", tests)):
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 2000000:
            raise AuditError("missing/unsafe Gradle dependency report")
        src = path.read_text(encoding="utf-8")
        if "BUILD SUCCESSFUL" not in src:
            raise AuditError("selected Gradle dependency report not successful")
        graphs[label] = bool(match.search(src))
    if not any(graphs.values()):
        raise AuditError("selected concurrent-futures 1.1.0 not in Gradle runtime/test graph")
    folder = cache / "androidx.concurrent" / "concurrent-futures" / "1.1.0"
    for component in (cache, cache / "androidx.concurrent", cache / "androidx.concurrent" / "concurrent-futures", folder):
        if component.is_symlink():
            raise AuditError("symlinked Gradle module cache")
    cached = sorted(folder.glob("*/concurrent-futures-1.1.0.jar"))
    if len(cached) != 1 or cached[0].is_symlink() or cached[0].parent.is_symlink():
        raise AuditError("ambiguous/missing exact selected cached JAR")
    if not 0 < cached[0].stat().st_size <= LIMITS[JAR_URL]:
        raise AuditError("cached JAR size invalid")
    local = cached[0].read_bytes()
    samples = {url: getter(url) for url in (POM_URL, JAR_URL, NOTICE_URL, LICENSE_URL, TREE_URL)}
    if any(not isinstance(s, bytes) or not 0 < len(s) <= LIMITS[url] for url, s in samples.items()):
        raise AuditError("invalid official upstream response bytes")
    pom, jar, notice, licence, tree = (samples[url] for url in (POM_URL, JAR_URL, NOTICE_URL, LICENSE_URL, TREE_URL))
    if POM_SHA256 and sha(pom) != POM_SHA256:
        raise AuditError("official Maven POM SHA pin mismatch")
    if JAR_SHA256 and sha(jar) != JAR_SHA256:
        raise AuditError("official Maven JAR SHA pin mismatch")
    pominfo, jarinfo, treeinfo = validate_pom(pom), validate_jar(jar), validate_tree(tree)
    if sha(local) != sha(jar) or len(local) != len(jar):
        raise AuditError("selected Gradle JAR not byte-identical to Google Maven")
    if blob(notice) != SNAPSHOT_NOTICE_BLOB or "kotlinx.coroutines" not in notice.decode("utf-8"):
        raise AuditError("pinned 2026 module NOTICE source mismatch")
    if blob(licence) != SNAPSHOT_LICENSE_BLOB or b"Apache License" not in licence:
        raise AuditError("pinned AndroidX root LICENSE mismatch")
    return {"schemaVersion": 1, "purl": PURL,
            "status": "GOOGLE_MAVEN_GRADLE_JAR_BYTES_MATCH_LATER_SOURCE_NOTICE_ONLY",
            "selectedGradleConfigurations": graphs,
            "officialPOM": dict(pominfo, url=POM_URL, sha256=sha(pom), bytes=len(pom)),
            "officialJAR": dict(jarinfo, url=JAR_URL, sha256=sha(jar), bytes=len(jar), gradleByteParity=True),
            "laterSourceNotice": {"url": NOTICE_URL, "gitBlob": blob(notice),
                                  "sha256": sha(notice), "bytes": len(notice),
                                  "2020ReleasedJarObligation": "NOT_VERIFIED"},
            "upstreamLicense": {"url": LICENSE_URL, "gitBlob": blob(licence),
                                "sha256": sha(licence), "bytes": len(licence)},
            "laterSourceModule": treeinfo,
            "hashPinsVerified": bool(POM_SHA256 and JAR_SHA256),
            "android85MissingNoticeRowsOpen": True, "gradle42PomGapsOpen": True,
            "noticeClosure": "NOT_VERIFIED", "licenseClosure": "NOT_VERIFIED",
            "publisherSignatureVerified": False, "sourceReproducible": False,
            "sbomComplete": False, "releaseApproved": False}


def main() -> int:
    p = argparse.ArgumentParser()
    for name in ("cache", "runtime", "test", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    try:
        result = audit(args.cache, args.runtime, args.test)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        for key, val in (("FUTURES110_GOOGLE_POM_SHA256", result["officialPOM"]["sha256"]),
                         ("FUTURES110_GOOGLE_JAR_SHA256", result["officialJAR"]["sha256"]),
                         ("FUTURES110_LATER_NOTICE_SHA256", result["laterSourceNotice"]["sha256"]),
                         ("FUTURES110_LICENSE_SHA256", result["upstreamLicense"]["sha256"]),
                         ("FUTURES110_GOOGLE_JAR_BYTES", result["officialJAR"]["bytes"]),
                         ("FUTURES110_JAR_EMBEDDED_LEGAL", result["officialJAR"]["embeddedLegalFilenames"]),
                         ("FUTURES110_GRADLE_BYTE_PARITY", result["officialJAR"]["gradleByteParity"]),
                         ("FUTURES110_NOTICE_CLOSURE", result["noticeClosure"])):
            print(key, val)
        return 0
    except (AuditError, OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        args.output.write_text(json.dumps({
            "purl": PURL, "status": "BLOCKED_SOURCE_NOT_VERIFIED", "error": str(exc),
            "noticeClosure": "NOT_VERIFIED", "licenseClosure": "NOT_VERIFIED",
            "android85MissingNoticeRowsOpen": True, "gradle42PomGapsOpen": True,
            "releaseApproved": False}, indent=2) + "\n", encoding="utf-8")
        print("BLOCKED FUTURES110 SOURCE:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
