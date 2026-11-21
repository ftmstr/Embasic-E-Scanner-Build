#!/usr/bin/env python3
"""One exact Kotlin stdlib Maven/Gradle and immutable-tag legal-source probe.

Evidence is scoped to Android Gradle-resolved kotlin-stdlib 2.3.21.
NO downstream license grant, APK inclusion, publisher signature or release GO.
The Kotlin source NOTICE describes the compiler distribution; applicability
to the stdlib JAR is deliberately NOT VERIFIED.
"""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import sys
from urllib import request
import xml.etree.ElementTree as ET
import zipfile

PURL = "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.3.21"
TAG_COMMIT = "fea1ad8c18995b80d1ca0e3917056104613d23db"
BASE = "https://repo.maven.apache.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/2.3.21/"
POM = BASE + "kotlin-stdlib-2.3.21.pom"
JAR = BASE + "kotlin-stdlib-2.3.21.jar"
LICENSE = "https://raw.githubusercontent.com/JetBrains/kotlin/" + TAG_COMMIT + "/license/LICENSE.txt"
NOTICE = "https://raw.githubusercontent.com/JetBrains/kotlin/" + TAG_COMMIT + "/license/NOTICE.txt"
LIMITS = {POM: 65536, JAR: 6000000, LICENSE: 40000, NOTICE: 10000}
# Exact PUBLIC CI 44943058383, job 136964276999 (21-Nov-2026).
POM_SHA256 = "3e0b48daa14dc73f8029d8d9e15ed32940377caf7b915510f88d33219b350186"
JAR_SHA256 = "6f64eac736db9434dd6925b4a518b9d1d17177652320c37916cf9ba3ce7d7d7a"
# Exact immutable JetBrains/kotlin tag v2.3.21 Git tree blob identities.
LICENSE_BLOB = "d645695673349e3947e8e5ae42332d0ac3164cd7"
NOTICE_BLOB = "80dbbefa483f605b7e69a1458f9f66b277b61988"


class AuditError(ValueError):
    pass


class DenyRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("upstream redirect rejected")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def fetch(url: str) -> bytes:
    if url not in LIMITS:
        raise AuditError("unallowlisted source URL")
    req = request.Request(url, headers={"User-Agent": "Embasic-E-Scanner-KotlinStdlib23121-SourceProbe/1",
                                        "Accept": "application/octet-stream"})
    try:
        with request.build_opener(DenyRedirect).open(req, timeout=15) as stream:
            if stream.status != 200:
                raise AuditError("unexpected upstream HTTP status")
            raw = stream.read(LIMITS[url] + 1)
    except OSError as exc:
        raise AuditError("upstream unavailable") from exc
    if not 0 < len(raw) <= LIMITS[url]:
        raise AuditError("upstream byte bound violated")
    return raw


def validate_pom(raw: bytes) -> str:
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise AuditError("unsafe Maven POM")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AuditError("malformed Maven POM") from exc
    def field(n, tag):
        values = [(x.text or "").strip() for x in n if x.tag.rsplit("}", 1)[-1] == tag]
        if len(values) != 1:
            raise AuditError("ambiguous POM field " + tag)
        return values[0]
    for key, expected in (("groupId", "org.jetbrains.kotlin"),
                          ("artifactId", "kotlin-stdlib"), ("version", "2.3.21")):
        if field(root, key) != expected:
            raise AuditError("POM coordinate mismatch")
    licenses = [x for x in root if x.tag.rsplit("}", 1)[-1] == "licenses"]
    if len(licenses) != 1:
        raise AuditError("missing direct POM legal label")
    entries = [x for x in licenses[0] if x.tag.rsplit("}", 1)[-1] == "license"]
    if len(entries) != 1:
        raise AuditError("ambiguous legal label")
    name = field(entries[0], "name")
    if "apache" not in name.lower() or "2.0" not in name:
        raise AuditError("unexpected supplier POM legal label")
    return name


def audit(cache: Path, runtime: Path, testing: Path, get=fetch) -> dict:
    for path in (runtime, testing):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2000000:
            raise AuditError("invalid Gradle resolved report")
        content = path.read_text(encoding="utf-8")
        if "BUILD SUCCESSFUL" not in content or "org.jetbrains.kotlin:kotlin-stdlib:2.3.21" not in content:
            raise AuditError("exact resolved Gradle module not evidenced")
    folder = cache / "org.jetbrains.kotlin" / "kotlin-stdlib" / "2.3.21"
    for path in (cache, cache / "org.jetbrains.kotlin", cache / "org.jetbrains.kotlin" / "kotlin-stdlib", folder):
        if path.is_symlink():
            raise AuditError("symlinked cache boundary")
    hits = list(folder.glob("*/kotlin-stdlib-2.3.21.jar"))
    if len(hits) != 1 or hits[0].is_symlink() or hits[0].parent.is_symlink():
        raise AuditError("missing/ambiguous exact Gradle JAR")
    if hits[0].stat().st_size > LIMITS[JAR]:
        raise AuditError("oversized local Gradle JAR")
    local = hits[0].read_bytes()
    pom, jar, license_raw, notice_raw = [get(url) for url in (POM, JAR, LICENSE, NOTICE)]
    if sha(pom) != POM_SHA256 or sha(jar) != JAR_SHA256:
        raise AuditError("official Maven source hash pin mismatch")
    if blob(license_raw) != LICENSE_BLOB or blob(notice_raw) != NOTICE_BLOB:
        raise AuditError("immutable upstream legal source blob pin mismatch")
    name = validate_pom(pom)
    if not zipfile.is_zipfile(BytesIO(jar)) or len(jar) > LIMITS[JAR]:
        raise AuditError("invalid Maven JAR")
    with zipfile.ZipFile(BytesIO(jar)) as zf:
        members = zf.infolist()
        if len(members) > 30000 or sum(x.file_size for x in members) > 120000000:
            raise AuditError("oversized JAR ZIP members")
        if not any(x.filename == "kotlin/Unit.class" for x in members):
            raise AuditError("stdlib binary signature class missing")
    if len(local) != len(jar) or sha(local) != sha(jar):
        raise AuditError("Gradle/Maven JAR byte mismatch")
    if b"Apache License" not in license_raw or b"Version 2.0" not in license_raw:
        raise AuditError("tag license text mismatch")
    if b"Kotlin Compiler distribution" not in notice_raw:
        raise AuditError("tag NOTICE scope changed; manual review required")
    return {
        "schemaVersion": 1, "purl": PURL, "status": "EXACT_MAVEN_GRADLE_BYTES_MATCH_LEGAL_OPEN",
        "mavenPOM": {"url": POM, "sha256": sha(pom), "size": len(pom), "supplierLabel": name},
        "mavenJAR": {"url": JAR, "sha256": sha(jar), "size": len(jar), "gradleByteParity": True},
        "taggedLicense": {"url": LICENSE, "sha256": sha(license_raw),
                          "gitBlobSha1": blob(license_raw), "size": len(license_raw)},
        "taggedNotice": {"url": NOTICE, "sha256": sha(notice_raw),
                         "gitBlobSha1": blob(notice_raw), "size": len(notice_raw),
                         "appliesToStdlibJar": "NOT_VERIFIED_COMPILER_SCOPE"},
        "tagCommit": TAG_COMMIT, "publisherSignatureVerified": False,
        "apkPackagingVerified": False, "redistributionRightsVerified": False,
        "noticeClosure": "NOT_VERIFIED", "licenseClosure": "NOT_VERIFIED",
        "independent42GradlePomGapsOpen": True, "sbomComplete": False,
        "releaseApproved": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = audit(args.cache, args.runtime, args.test)
        args.output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print("KOTLIN_STDLIB_EXACT_POM_SHA256", evidence["mavenPOM"]["sha256"])
        print("KOTLIN_STDLIB_EXACT_JAR_SHA256", evidence["mavenJAR"]["sha256"])
        print("KOTLIN_STDLIB_LICENSE_SHA256", evidence["taggedLicense"]["sha256"])
        print("KOTLIN_STDLIB_NOTICE_SHA256", evidence["taggedNotice"]["sha256"])
        print("KOTLIN_STDLIB_LICENSE_GIT_BLOB", evidence["taggedLicense"]["gitBlobSha1"])
        print("KOTLIN_STDLIB_NOTICE_GIT_BLOB", evidence["taggedNotice"]["gitBlobSha1"])
        print("KOTLIN_STDLIB_GRADLE_MAVEN_PARITY", evidence["mavenJAR"]["gradleByteParity"])
        print("KOTLIN_STDLIB_RELEASE_APPROVED", False)
        return 0
    except (AuditError, OSError, ValueError, UnicodeError, zipfile.BadZipFile) as exc:
        print("BLOCKED Kotlin stdlib 2.3.21 source review:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
