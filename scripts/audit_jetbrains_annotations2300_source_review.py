#!/usr/bin/env python3
"""One Android Gradle-selected JetBrains annotations 23.0.0 Maven/source probe.

Does not clear any Android NOTICE row, parent POM, legal obligation or release gate.
Upstream tagged source has a LICENSE.txt but no NOTICE file in its exact tree.
"""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import sys
from urllib import error, request
import xml.etree.ElementTree as ET
import zipfile

PURL = "pkg:maven/org.jetbrains/annotations@23.0.0"
COORDINATE = "org.jetbrains:annotations:23.0.0"
TAG_COMMIT = "5d06c0c48e0a4fe44b2bc0d5d3e8b113c7a57de2"
LICENSE_BLOB = "4c4a741bfd6103cc173315b0c699ea93bfe71383"
BASE = "https://repo.maven.apache.org/maven2/org/jetbrains/annotations/23.0.0/"
POM = BASE + "annotations-23.0.0.pom"
JAR = BASE + "annotations-23.0.0.jar"
LICENSE = "https://raw.githubusercontent.com/JetBrains/java-annotations/" + TAG_COMMIT + "/LICENSE.txt"
TAG_TREE_SHA = "409e01e2a372f76692a4737c007b5ad8719ffb82"
TAG_TREE = "https://api.github.com/repos/JetBrains/java-annotations/git/trees/" + TAG_TREE_SHA + "?recursive=1"
LIMITS = {POM: 65536, JAR: 2000000, LICENSE: 20000, TAG_TREE: 250000}
# Set to observed full-byte official hashes only after independent live CI.
POM_SHA256 = ""
JAR_SHA256 = ""


class AuditError(ValueError):
    pass


class DenyRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("redirect rejected")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def fetch(url: str) -> bytes:
    if url not in LIMITS:
        raise AuditError("unallowlisted upstream URL")
    req = request.Request(url, headers={
        "User-Agent": "Embasic-E-Scanner-Annotations2300-ScopeAudit/1",
        "Accept": "application/octet-stream",
    })
    try:
        with request.build_opener(DenyRedirect).open(req, timeout=20) as stream:
            if stream.status != 200:
                raise AuditError("upstream HTTP status not 200")
            raw = stream.read(LIMITS[url] + 1)
    except error.HTTPError as exc:
        raise AuditError("official source HTTP " + str(exc.code) + ": " +
                         ("MAVEN_POM" if url == POM else "MAVEN_JAR" if url == JAR
                          else "TAGGED_LICENSE" if url == LICENSE else "TAG_TREE")) from exc
    except (error.URLError, OSError, TimeoutError) as exc:
        raise AuditError("official source transport unavailable: " +
                         ("MAVEN_POM" if url == POM else "MAVEN_JAR" if url == JAR
                          else "TAGGED_LICENSE" if url == LICENSE else "TAG_TREE")) from exc
    if not 0 < len(raw) <= LIMITS[url]:
        raise AuditError("official source byte bound violated")
    return raw


def direct_field(parent: ET.Element, name: str) -> str:
    values = [(x.text or "").strip() for x in parent if x.tag.rsplit("}", 1)[-1] == name]
    if len(values) != 1 or not values[0]:
        raise AuditError("missing or ambiguous direct POM field: " + name)
    return values[0]


def validate_pom(raw: bytes) -> str:
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise AuditError("POM XML entity/doctype refused")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AuditError("invalid official POM") from exc
    if root.tag.rsplit("}", 1)[-1] != "project":
        raise AuditError("unexpected POM root")
    for key, expected in (("groupId", "org.jetbrains"),
                          ("artifactId", "annotations"), ("version", "23.0.0")):
        if direct_field(root, key) != expected:
            raise AuditError("official Maven POM coordinate mismatch")
    licenses = [x for x in root if x.tag.rsplit("}", 1)[-1] == "licenses"]
    if len(licenses) != 1:
        raise AuditError("supplier POM has no unambiguous direct license claim")
    labels = [x for x in licenses[0] if x.tag.rsplit("}", 1)[-1] == "license"]
    if len(labels) != 1:
        raise AuditError("multiple or missing POM license entries")
    label = direct_field(labels[0], "name")
    if "apache" not in label.lower() or "2.0" not in label:
        raise AuditError("unexpected supplier POM license claim")
    return label


def validate_tag_tree(raw: bytes) -> int:
    try:
        tree = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise AuditError("invalid immutable Git tree JSON") from exc
    if not isinstance(tree, dict) or tree.get("sha") != TAG_TREE_SHA or tree.get("truncated") is not False:
        raise AuditError("GitHub tag tree changed, incomplete or unverified")
    entries = tree.get("tree")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 2000:
        raise AuditError("GitHub tagged source tree absent or oversized")
    licenses = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == "LICENSE.txt"]
    if len(licenses) != 1 or licenses[0].get("type") != "blob" or licenses[0].get("sha") != LICENSE_BLOB:
        raise AuditError("tagged LICENSE blob does not match immutable tag")
    # This is a precise absence claim about this tree, not a waiver of Section 4(d).
    notices = [entry.get("path", "") for entry in entries if isinstance(entry, dict)
               and isinstance(entry.get("path"), str)
               and entry["path"].rsplit("/", 1)[-1].lower() in ("notice", "notice.txt", "notice.md")]
    if notices:
        raise AuditError("tagged source NOTICE present: require separate exact-text review")
    return len(entries)


def validate_jar(raw: bytes) -> list[str]:
    if len(raw) > LIMITS[JAR] or not zipfile.is_zipfile(BytesIO(raw)):
        raise AuditError("invalid bounded Maven JAR")
    with zipfile.ZipFile(BytesIO(raw)) as zf:
        entries = zf.infolist()
        if len(entries) > 5000 or sum(x.file_size for x in entries) > 30000000:
            raise AuditError("ZIP member count or expanded size exceeded")
        names = [x.filename for x in entries]
        if len(names) != len(set(names)) or "org/jetbrains/annotations/NotNull.class" not in names:
            raise AuditError("bad JAR or duplicate/class signature")
        if zf.testzip() is not None:
            raise AuditError("JAR CRC failed")
        return sorted(x for x in names if x.rsplit("/", 1)[-1].lower()
                      in ("license", "license.txt", "notice", "notice.txt", "notice.md"))


def audit(cache: Path, runtime: Path, testing: Path, get=fetch) -> dict:
    selected = {}
    pattern = re.compile(r"(?<![A-Za-z0-9_.-])org\.jetbrains:annotations:23\.0\.0(?![A-Za-z0-9_.-])")
    for name, path in (("debugRuntimeClasspath", runtime), ("debugUnitTestRuntimeClasspath", testing)):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2000000:
            raise AuditError("missing, symlinked or oversized resolved Gradle report")
        data = path.read_text(encoding="utf-8")
        if "BUILD SUCCESSFUL" not in data:
            raise AuditError("resolved Gradle report not successful")
        selected[name] = bool(pattern.search(data))
    if not any(selected.values()):
        raise AuditError("module not selected in either actual Gradle graph")
    folder = cache / "org.jetbrains" / "annotations" / "23.0.0"
    for path in (cache, cache / "org.jetbrains", cache / "org.jetbrains" / "annotations", folder):
        if path.is_symlink():
            raise AuditError("symlinked cache boundary")
    hits = list(folder.glob("*/annotations-23.0.0.jar"))
    if len(hits) != 1 or hits[0].is_symlink() or hits[0].parent.is_symlink():
        raise AuditError("Gradle JAR absent or ambiguous")
    if hits[0].stat().st_size > LIMITS[JAR]:
        raise AuditError("cached JAR too large")
    local = hits[0].read_bytes()
    pom, jar, legal, tree = [get(u) for u in (POM, JAR, LICENSE, TAG_TREE)]
    for url, raw in zip((POM, JAR, LICENSE, TAG_TREE), (pom, jar, legal, tree)):
        if not 0 < len(raw) <= LIMITS[url]:
            raise AuditError("upstream bytes too large or empty")
    if POM_SHA256 and sha(pom) != POM_SHA256:
        raise AuditError("pinned Maven POM hash mismatch")
    if JAR_SHA256 and sha(jar) != JAR_SHA256:
        raise AuditError("pinned Maven JAR hash mismatch")
    claim = validate_pom(pom)
    embedded = validate_jar(jar)
    if blob(legal) != LICENSE_BLOB or b"Apache License" not in legal or b"Version 2.0" not in legal:
        raise AuditError("tagged upstream LICENSE bytes changed")
    tree_count = validate_tag_tree(tree)
    if len(local) != len(jar) or sha(local) != sha(jar):
        raise AuditError("actual Gradle/Maven JAR byte mismatch")
    return {
        "schemaVersion": 1, "purl": PURL,
        "status": "SOURCE_BYTE_PARITY_VERIFIED_LEGAL_OPEN",
        "selectedGradleGraphs": selected,
        "mavenPOM": {"url": POM, "sha256": sha(pom), "size": len(pom), "supplierLicenseClaim": claim},
        "mavenJAR": {"url": JAR, "sha256": sha(jar), "size": len(jar),
                     "gradleByteParity": True, "embeddedLegalFileNames": embedded},
        "tagCommit": TAG_COMMIT, "tagTreeSha": TAG_TREE_SHA,
        "taggedLicense": {"url": LICENSE, "sha256": sha(legal),
                          "gitBlobSha1": blob(legal), "size": len(legal)},
        "taggedNotice": {"treeUrl": TAG_TREE, "entriesScanned": tree_count,
                         "taggedTreeFileStatus": "ABSENT_IN_EXACT_TAGGED_TREE",
                         "downstreamNoticeObligations": "NOT_VERIFIED"},
        "liveMavenHashPinsVerified": bool(POM_SHA256 and JAR_SHA256),
        "publisherSignatureVerified": False, "apkPackagingVerified": False,
        "redistributionRightsVerified": False, "licenseClosure": "NOT_VERIFIED",
        "noticeClosure": "NOT_VERIFIED", "independent42GradlePomGapsOpen": True,
        "full85AndroidNoticeRowsStillOpen": True, "sbomComplete": False, "releaseApproved": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--test", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = audit(args.cache, args.runtime, args.test)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        for field, key in (("POM", "mavenPOM"), ("JAR", "mavenJAR"), ("LICENSE", "taggedLicense")):
            print("ANNOTATIONS2300_" + field + "_SHA256", result[key]["sha256"])
        print("ANNOTATIONS2300_LICENSE_GIT_BLOB", result["taggedLicense"]["gitBlobSha1"])
        print("ANNOTATIONS2300_NOTICE_IN_TAG", result["taggedNotice"]["taggedTreeFileStatus"])
        print("ANNOTATIONS2300_GRADLE_PARITY", result["mavenJAR"]["gradleByteParity"])
        print("ANNOTATIONS2300_LEGAL_CLOSURE", result["licenseClosure"])
        return 0
    except (AuditError, OSError, ValueError, UnicodeError, zipfile.BadZipFile) as exc:
        print("BLOCKED annotations 23.0.0 source review:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
