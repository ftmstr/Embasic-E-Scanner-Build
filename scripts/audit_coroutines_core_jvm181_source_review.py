#!/usr/bin/env python3
"""Exact kotlinx-coroutines-core-jvm 1.8.1 Maven POM/JAR and tagged source LICENSE byte gate.

One observed Android resolved module only. This is not an SBOM, APK contents
proof, copyright clearance, a verified publisher signature or release approval.
Inputs are bounded; official HTTPS origins are immutable allowlisted literals.
"""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import sys
from urllib import error, request
import xml.etree.ElementTree as ET
import zipfile

from audit_android_dependency_graph import resolved_graph

PURL = "pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm@1.8.1"
COORDINATE = ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.8.1")
TAG_COMMIT = "cd696d3f8f4afdbc735915c2bded974616331b55"
TAG_LICENSE_GIT_BLOB = "9c308d958bf91eafe83f66106ca692ff414a4965"
# Exact upstream LICENSE Git blob is independently verified at tag 1.8.1.
# Official Maven SHA-256 pins require real CI; no guessed source hashes.

BASE = "https://repo.maven.apache.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.8.1/"
POM_URL = BASE + "kotlinx-coroutines-core-jvm-1.8.1.pom"
JAR_URL = BASE + "kotlinx-coroutines-core-jvm-1.8.1.jar"
LICENSE_URL = ("https://raw.githubusercontent.com/Kotlin/kotlinx.coroutines/"
               + TAG_COMMIT + "/LICENSE.txt")
MAX_REPORT = 2_000_000
MAX_POM = 64_000
MAX_JAR = 3_000_000
MAX_LICENSE = 32_000
MAX_ZIP_EXPANDED = 50_000_000


class AuditError(ValueError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("unverified upstream redirect")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def bounded_read(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise AuditError("missing, symlinked or oversized input: " + path.name)
    data = path.read_bytes()
    if not 0 < len(data) <= limit:
        raise AuditError("input content outside bounds")
    return data


def read_cached_jar(cache: Path) -> bytes:
    # Gradle's canonical hash-prefixed cache layout; no arbitrary file search.
    relative = ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.8.1")
    for depth in range(1, 4):
        check = cache.joinpath(*relative[:depth])
        if check.is_symlink():
            raise AuditError("symlinked Gradle cache boundary")
    folder = cache.joinpath(*relative)
    if folder.is_symlink() or not folder.is_dir():
        raise AuditError("coroutines core JVM Gradle cache missing")
    candidates = sorted(folder.glob("*/kotlinx-coroutines-core-jvm-1.8.1.jar"))
    if len(candidates) != 1 or candidates[0].parent.is_symlink():
        raise AuditError("missing or ambiguous exact cached JAR")
    return bounded_read(candidates[0], MAX_JAR)


def official_fetch(url: str, limit: int) -> bytes:
    if url not in (POM_URL, JAR_URL, LICENSE_URL):
        raise AuditError("unapproved remote URL")
    maximum = {POM_URL: MAX_POM, JAR_URL: MAX_JAR,
               LICENSE_URL: MAX_LICENSE}[url]
    if limit != maximum:
        raise AuditError("unexpected source bound")
    req = request.Request(url, headers={
        "Accept": "application/octet-stream",
        "User-Agent": "Embasic-E-Scanner-PUBLIC-CoroutinesCoreJvm181-Provenance/1",
    })
    try:
        with request.build_opener(NoRedirect).open(req, timeout=14) as conn:
            if conn.status != 200:
                raise AuditError("unexpected official source HTTP response")
            raw = conn.read(limit + 1)
    except (error.URLError, error.HTTPError, TimeoutError, OSError) as exc:
        raise AuditError("official HTTPS source unavailable") from exc
    if not 0 < len(raw) <= limit:
        raise AuditError("empty or oversized source bytes")
    return raw


def validate_pom(raw: bytes) -> str:
    if len(raw) > MAX_POM or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise AuditError("unsafe XML POM")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AuditError("malformed supplier POM") from exc
    def child(node: ET.Element, name: str) -> str:
        values = [x.text.strip() if x.text else "" for x in node
                  if x.tag.split("}")[-1] == name]
        return values[0] if len(values) == 1 else ""
    for field, exact in zip(("groupId", "artifactId", "version"), COORDINATE):
        if child(root, field) != exact:
            raise AuditError("supplier POM coordinate mismatch: " + field)
    licenses = [node for node in root if node.tag.split("}")[-1] == "licenses"]
    if len(licenses) != 1:
        raise AuditError("missing direct POM license declaration")
    entries = [node for node in licenses[0] if node.tag.split("}")[-1] == "license"]
    if len(entries) != 1:
        raise AuditError("ambiguous direct POM licenses")
    name = child(entries[0], "name")
    if "apache" not in name.lower() or "2.0" not in name:
        raise AuditError("unexpected supplier POM license name")
    return name


def inspect_jar(raw: bytes) -> list[str]:
    if len(raw) > MAX_JAR or not zipfile.is_zipfile(BytesIO(raw)):
        raise AuditError("invalid or oversized Maven JAR")
    with zipfile.ZipFile(BytesIO(raw)) as jar:
        entries = jar.infolist()
        if len(entries) > 8192 or len({x.filename for x in entries}) != len(entries):
            raise AuditError("duplicate or unbounded JAR members")
        if any(x.flag_bits & 1 or x.file_size > MAX_ZIP_EXPANDED or
               x.filename.startswith("/") or ".." in x.filename.split("/")
               or "\\" in x.filename for x in entries):
            raise AuditError("unsafe JAR member")
        if sum(x.file_size for x in entries) > MAX_ZIP_EXPANDED:
            raise AuditError("oversized uncompressed Maven JAR")
        files = {x.filename for x in entries}
        for needed in ("kotlinx/coroutines/Job.class",
                       "kotlinx/coroutines/BuildersKt.class"):
            if needed not in files:
                raise AuditError("coroutines core JVM class signatures absent from JAR")
        return sorted(x for x in files if
                      x.upper().startswith("META-INF/") and
                      ("LICENSE" in x.upper() or "NOTICE" in x.upper()))


def audit_bundle(runtime_text: str, test_text: str, pom: bytes, jar: bytes,
                 upstream_license: bytes, cached_jar: bytes,
                 license_blob: str = TAG_LICENSE_GIT_BLOB,
                 expected_shas: dict[str, str] | None = None) -> dict:
    runtime = resolved_graph(runtime_text, "debugRuntimeClasspath")
    testing = resolved_graph(test_text, "debugUnitTestRuntimeClasspath")
    runtime_selected = COORDINATE in runtime
    test_selected = COORDINATE in testing
    if not (runtime_selected or test_selected):
        raise AuditError("coroutines core JVM 1.8.1 not observed in resolved Android graph")
    # A changed selected version is not silently matched to the old license.
    for group, artifact, version in runtime + testing:
        if (group, artifact) == COORDINATE[:2] and version != COORDINATE[2]:
            raise AuditError("selected coroutines core JVM version drift")
    license_name = validate_pom(pom)
    # First live source inspection has no invented exact Maven pins.
    # Verified SHA-256 pins are added only after actual official-source CI.
    if expected_shas is not None:
        if ({key: digest(value) for key, value in {
                "pom": pom, "jar": jar, "license": upstream_license}.items()}
                != expected_shas):
            raise AuditError("exact pinned Maven/tag source SHA256 drift")
    if (not 0 < len(upstream_license) <= MAX_LICENSE or
            git_blob(upstream_license) != license_blob or
            b"Apache License" not in upstream_license or
            b"Version 2.0" not in upstream_license):
        raise AuditError("exact 1.8.1 tagged LICENSE blob mismatch")
    members = inspect_jar(jar)
    if len(cached_jar) != len(jar) or digest(cached_jar) != digest(jar):
        raise AuditError("official Maven JAR vs Gradle cache BYTE_MISMATCH")
    return {
        "schemaVersion": 1,
        "purl": PURL,
        "status": "EXACT_MAVEN_TAG_BYTES_MATCH_LEGAL_REVIEW_OPEN",
        "scope": "single Gradle-resolved Android dependency, not an APK audit",
        "debugRuntimeSelected": runtime_selected,
        "unitTestRuntimeSelected": test_selected,
        "mavenPom": {"url": POM_URL, "sha256": digest(pom), "byteSize": len(pom),
                     "supplierDeclaredLicenseName": license_name,
                     "licenseGrantVerified": False},
        "mavenJar": {"url": JAR_URL, "sha256": digest(jar), "byteSize": len(jar),
                     "localGradleBytesMatch": True,
                     "embeddedLegalFilenames": members,
                     "embeddedLegalTextByteParityVerified": False},
        "taggedLicense": {
            "tag": "1.8.1", "commit": TAG_COMMIT,
            "url": LICENSE_URL, "gitBlobSha1": git_blob(upstream_license),
            "sha256": digest(upstream_license), "byteSize": len(upstream_license),
            "tagCryptographicallySigned": False,
        },
        "sourceHashPinsVerified": False,
        "publisherSignatureVerified": False,
        "apkPackagingVerified": False,
        "redistributionRightsVerified": False,
        "fullRuntimeDependencyNoticeClosure": False,
        "independent42PluginPomReviewStillOpen": True,
        "licenseClosure": "NOT_VERIFIED",
        "noticeClosure": "NOT_VERIFIED",
        "sbomComplete": False,
        "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = {
        "schemaVersion": 1, "purl": PURL,
        "status": "BLOCKED_SOURCE_NOT_VERIFIED",
        "licenseClosure": "NOT_VERIFIED", "noticeClosure": "NOT_VERIFIED",
        "sbomComplete": False, "releaseApproved": False,
    }
    try:
        runtime = bounded_read(args.runtime, MAX_REPORT).decode("utf-8")
        testing = bounded_read(args.test, MAX_REPORT).decode("utf-8")
        cache_bytes = read_cached_jar(args.cache)
        report = audit_bundle(runtime, testing,
                              official_fetch(POM_URL, MAX_POM),
                              official_fetch(JAR_URL, MAX_JAR),
                              official_fetch(LICENSE_URL, MAX_LICENSE),
                              cache_bytes)
    except (AuditError, OSError, ValueError, UnicodeError) as exc:
        report["blocker"] = str(exc)[:240]
    try:
        if args.output.is_symlink() or not args.output.parent.is_dir():
            raise AuditError("invalid output destination")
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (OSError, AuditError) as exc:
        print("BLOCKED: source evidence output unavailable: " + str(exc), file=sys.stderr)
        return 2
    print("COROUTINES_CORE_JVM181_SOURCE_EVIDENCE " + json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "EXACT_MAVEN_TAG_BYTES_MATCH_LEGAL_REVIEW_OPEN" else 2


if __name__ == "__main__":
    raise SystemExit(main())
