#!/usr/bin/env python3
"""Jakarta Activation API 1.2.1 exact Maven/tagged BSD-3-Clause evidence.

Build-tool metadata and immutable-source research ONLY. This code does not
elect a license, infer child rights from parent/EE4J organization, verify
publisher signatures, or approve APK/MSIX redistribution.
"""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
import stat
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
import re
import sys
from urllib import request, error

from audit_jaf120_exact_license import (
    AuditError, NoRedirect, _git_blob_sha1, _pom,
    _read, _sha,
)

PURL = "pkg:maven/jakarta.activation/jakarta.activation-api@1.2.1"
PARENT_COORD = "com.sun.activation:all:1.2.1"
COMPANY_ANCESTOR = "org.eclipse.ee4j:project:1.0.2"
VERSION_COMMIT = "41bad0bd6ba821abd8652c80e8e3c50b55851da2"
ANNOTATED_TAG_SHA = "74a1e74bf03213a0bb16e8e2392933aa47c233f3"
TAG_SIGNED = False
UPSTREAM_BASE = "https://raw.githubusercontent.com/jakartaee/jaf-api/" + VERSION_COMMIT
MAVEN_BASE = "https://repo.maven.apache.org/maven2"
CHILD_POM = MAVEN_BASE + "/jakarta/activation/jakarta.activation-api/1.2.1/jakarta.activation-api-1.2.1.pom"
CHILD_JAR = MAVEN_BASE + "/jakarta/activation/jakarta.activation-api/1.2.1/jakarta.activation-api-1.2.1.jar"
PARENT_POM = MAVEN_BASE + "/com/sun/activation/all/1.2.1/all-1.2.1.pom"
TAG_LICENSE = UPSTREAM_BASE + "/LICENSE.md"
TAG_NOTICE = UPSTREAM_BASE + "/NOTICE.md"
TAG_API_POM = UPSTREAM_BASE + "/activationapi/pom.xml"
TAG_BLOBS = {
    TAG_LICENSE: "e0358f972175d83cc567fcd129cc205ea9d40ff0",
    TAG_NOTICE: "d6492f81ccce4efec1e8d03248ca64d3b26c164f",
    TAG_API_POM: "09697c4589fb48882fb8ad28aaffe5d097054351",
}
LIMITS = {
    CHILD_POM: 65536, PARENT_POM: 65536,
    CHILD_JAR: 2_000_000,
    TAG_LICENSE: 16384, TAG_NOTICE: 16384, TAG_API_POM: 65536,
}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")



ARCHIVE_LICENSE = "META-INF/LICENSE.md"
ARCHIVE_NOTICE = "META-INF/NOTICE.md"


def _child_pom(raw: bytes) -> tuple[str, list[dict]]:
    """Exact Jakarta child inherits version from a *different* group parent."""
    if (not 0 < len(raw) <= 65536 or b"<!DOCTYPE" in raw.upper()
            or b"<!ENTITY" in raw.upper()):
        raise AuditError("unsafe Jakarta API POM bytes")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AuditError("malformed Jakarta API Maven POM") from exc
    def elem(path: str) -> str:
        return (root.findtext(path) or "").strip()
    parent = root.find("./{*}parent")
    if parent is None:
        raise AuditError("missing exact Jakarta API parent")
    parent_coord = ":".join((parent.findtext("./{*}" + k) or "").strip()
                             for k in ("groupId", "artifactId", "version"))
    if (elem("./{*}groupId") != "jakarta.activation"
            or elem("./{*}artifactId") != "jakarta.activation-api"
            or elem("./{*}version") not in ("", "1.2.1")
            or parent_coord != PARENT_COORD):
        raise AuditError("Maven child group/artifact/inherited-version/parent mismatch")
    licenses = root.findall("./{*}licenses/{*}license")
    return parent_coord, [
        {"name": (p.findtext("./{*}name") or "").strip()} for p in licenses
    ]


def _archive_legal_texts(raw: bytes) -> dict[str, bytes]:
    if not 0 < len(raw) <= LIMITS[CHILD_JAR]:
        raise AuditError("JAR exceeds allowed binary size")
    texts: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(BytesIO(raw)) as z:
            info = z.infolist()
            if not 0 < len(info) <= 2048:
                raise AuditError("unbounded JAR member count")
            seen: set[str] = set()
            unpacked = 0
            for member in info:
                name = member.filename
                parts = name.rstrip("/").split("/")
                if (not name or name.startswith(("/", "\\"))
                        or "\\" in name or ":" in name or "//" in name
                        or any(p in ("", ".", "..") for p in parts)
                        or name.casefold() in seen
                        or stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK):
                    raise AuditError("unsafe JAR path, symlink or duplicate")
                seen.add(name.casefold())
                unpacked += member.file_size
                if unpacked > 20_000_000:
                    raise AuditError("decompression bomb in JAR metadata")
                if name in (ARCHIVE_LICENSE, ARCHIVE_NOTICE):
                    if member.file_size > 16384 or name in texts:
                        raise AuditError("duplicate or oversized JAR legal text")
                    texts[name] = z.read(member)
    except (zipfile.BadZipFile, RuntimeError, EOFError, OSError) as exc:
        raise AuditError("malformed Maven JAR archive") from exc
    if set(texts) != {ARCHIVE_LICENSE, ARCHIVE_NOTICE} or any(not x for x in texts.values()):
        raise AuditError("missing exact JAR-embedded LICENSE.md/NOTICE.md")
    return texts

def retrieve(url: str) -> bytes:
    limit = LIMITS.get(url)
    if limit is None:
        raise AuditError("unallowlisted exact tag / Maven source URL")
    req = request.Request(url, headers={
        "User-Agent": "Embasic-E-Scanner-PUBLIC-Activation121-Evidence/1",
        "Accept": "application/octet-stream,application/xml,text/plain",
    })
    try:
        with request.build_opener(NoRedirect).open(req, timeout=12) as response:
            if response.status != 200:
                raise AuditError("unexpected exact upstream HTTP status")
            content = response.read(limit + 1)
    except (error.HTTPError, error.URLError, TimeoutError, OSError) as exc:
        raise AuditError("bounded exact upstream unavailable: " + str(exc)[:120]) from exc
    if not 0 < len(content) <= limit:
        raise AuditError("empty or oversized version-pinned bytes")
    return content


def _local(mod: dict, filename: str, limit: int) -> dict:
    files = mod.get("cachedFiles")
    if not isinstance(files, list) or not 1 <= len(files) <= 32:
        raise AuditError("missing/oversized local Maven cached file set")
    candidates = [f for f in files if isinstance(f, dict)
                  and f.get("filename") == filename]
    if len(candidates) != 1:
        raise AuditError("missing/duplicate exact local Maven file")
    f = candidates[0]
    if (not isinstance(f.get("sha256"), str)
            or not SHA256.fullmatch(f["sha256"])
            or type(f.get("byteSize")) is not int
            or not 0 < f["byteSize"] <= limit
            or f.get("sourceVerification") != "LOCAL_BYTES_ONLY"):
        raise AuditError("invalid local Maven size/hash/provenance")
    return f


def audit(inventory: dict, queue: dict, runtime: dict, fetch=retrieve,
          expected_blobs: dict[str, str] | None = None) -> dict:
    if expected_blobs is None:
        expected_blobs = TAG_BLOBS
    if (inventory.get("status") != "PASS_WITH_GAPS"
            or inventory.get("scope") != "Android Gradle root/app buildEnvironment LOCAL cache evidence only"
            or inventory.get("licenseApproval") != "NOT_VERIFIED"
            or inventory.get("originVerified") is not False
            or inventory.get("parentLicenseInheritanceVerified") is not False
            or inventory.get("releaseApproved") is not False
            or inventory.get("sbomComplete") is not False):
        raise AuditError("untrusted Gradle toolchain boundary/approval")
    modules = inventory.get("modules")
    if not isinstance(modules, list) or not modules:
        raise AuditError("missing selected Gradle build tool modules")
    candidates = [m for m in modules if isinstance(m, dict) and m.get("purl") == PURL]
    if len(candidates) != 1:
        raise AuditError("exact selected Activation121 coordinate missing/duplicate")
    m = candidates[0]
    scopes = m.get("scopes")
    if (m.get("licenseMetadataState") != "POM_WITHOUT_DIRECT_LICENSE_NAME"
            or m.get("pomDeclaredLicenses") != []
            or not isinstance(scopes, list) or not 1 <= len(scopes) <= 2
            or len(scopes) != len(set(scopes))
            or not set(scopes).issubset({"root", "app"})):
        raise AuditError("unexpected child direct POM state or plugin scope")
    local_pom = _local(m, "jakarta.activation-api-1.2.1.pom", 65536)
    local_jar = _local(m, "jakarta.activation-api-1.2.1.jar", LIMITS[CHILD_JAR])

    if (queue.get("status") != "REVIEW_QUEUE_ONLY_LEGAL_NO_GO"
            or queue.get("licenseClosure") != "NOT_VERIFIED"
            or queue.get("parentLicenseInheritanceVerified") is not False
            or queue.get("releaseApproved") is not False
            or queue.get("microsoftSDKBuildToolsExactRedistRights") !=
                "NOT_VERIFIED_SEPARATE_GATE"):
        raise AuditError("Gradle legal queue falsely escalated")
    qrows = queue.get("reviewQueue")
    if not isinstance(qrows, list) or len(qrows) != 42:
        raise AuditError("selected 42-child legal gaps missing")
    seen_review_purls = set()
    for record in qrows:
        if (not isinstance(record, dict)
                or not isinstance(record.get("purl"), str)
                or record["purl"] in seen_review_purls
                or record.get("licenseApproved") is not False
                or record.get("redistributionRightsVerified") is not False
                or record.get("parentLicenseInheritanceVerified") is not False
                or record.get("evidenceOnly") is not True):
            raise AuditError("42-child legal queue contains duplicate or forged approval")
        seen_review_purls.add(record["purl"])
    matches = [r for r in qrows if isinstance(r, dict) and r.get("purl") == PURL]
    if len(matches) != 1:
        raise AuditError("missing/duplicated exact Activation121 legal row")
    row = matches[0]
    if (row.get("directPomState") != "POM_WITHOUT_DIRECT_LICENSE_NAME"
            or row.get("complexParentMetadataReviewRequired") is not True
            or row.get("licenseApproved") is not False
            or row.get("redistributionRightsVerified") is not False
            or not {"EDL 1.0", "Eclipse Public License v. 2.0",
                    "GNU General Public License, version 2 with the GNU Classpath Exception"
                    }.issubset(set(row.get("complexParentLicenseMetadataNames", [])))):
        raise AuditError("direct child rights, enterprise ancestor hints or complex text drift")
    p_rows = row.get("cachedParentPOMReviewEvidence")
    if not isinstance(p_rows, list):
        raise AuditError("no parent cache SHA/provenance data")
    parents = [p for p in p_rows if isinstance(p, dict)
               and p.get("coordinate") == PARENT_COORD]
    if (len(parents) != 1
            or parents[0].get("status") != "PARENT_POM_METADATA_ONLY"
            or parents[0].get("unverifiedSupplierLicenseNames") != ["EDL 1.0"]
            or parents[0].get("licenseApproved") is not False
            or not isinstance(parents[0].get("localPOMSha256"), str)
            or not SHA256.fullmatch(parents[0]["localPOMSha256"])):
        raise AuditError("exact parent EDL POM cached bytes or status altered")
    ancestor = [p for p in p_rows if isinstance(p, dict)
                and p.get("coordinate") == COMPANY_ANCESTOR]
    if (len(ancestor) != 1 or ancestor[0].get("licenseApproved") is not False
            or ancestor[0].get("status") != "PARENT_POM_METADATA_ONLY"
            or not isinstance(ancestor[0].get("localPOMSha256"), str)
            or not SHA256.fullmatch(ancestor[0]["localPOMSha256"])):
        raise AuditError("organizational ancestor licence metadata boundary changed")
    if (runtime.get("graphAudit") != "PASS" or runtime.get("scope") !=
            "android-:app:debugRuntimeClasspath+debugUnitTestRuntimeClasspath"
            or runtime.get("inventoryCompleteness") != "PARTIAL"
            or runtime.get("pluginClasspathCovered") is not False
            or runtime.get("apkPackagingVerified") is not False
            or runtime.get("releaseApproved") is not False
            or runtime.get("licenseClosure") != "NOT_VERIFIED"):
        raise AuditError("unexpected Android app/test resolved-graph state")
    for config in ("runtimeComponents", "testComponents"):
        modules = runtime.get(config)
        if not isinstance(modules, list) or any(
                isinstance(v, dict) and v.get("purl") == PURL for v in modules):
            raise AuditError("new Activation121 app/test inclusion requires separate review")

    urls = (CHILD_POM, PARENT_POM, CHILD_JAR, TAG_LICENSE, TAG_NOTICE, TAG_API_POM)
    blobs = {url: fetch(url) for url in urls}
    if any(not isinstance(blobs[url], bytes) or
           not 0 < len(blobs[url]) <= LIMITS[url] for url in urls):
        raise AuditError("missing or oversized exact pinned upstream resource")
    for u in (TAG_LICENSE, TAG_NOTICE, TAG_API_POM):
        if _git_blob_sha1(blobs[u]) != expected_blobs.get(u):
            raise AuditError("immutable source tag Git blob changed")
    if (_sha(blobs[CHILD_POM]) != local_pom["sha256"]
            or len(blobs[CHILD_POM]) != local_pom["byteSize"]):
        raise AuditError("exact published Maven API POM differs from cache")
    if (_sha(blobs[CHILD_JAR]) != local_jar["sha256"]
            or len(blobs[CHILD_JAR]) != local_jar["byteSize"]):
        raise AuditError("exact published Maven API JAR differs from cache")
    if _sha(blobs[PARENT_POM]) != parents[0]["localPOMSha256"]:
        raise AuditError("exact Maven parent POM differs from cache SHA")
    parent, child_lic = _child_pom(blobs[CHILD_POM])
    if parent != PARENT_COORD or child_lic:
        raise AuditError("published child POM direct licence state or parent changed")
    _, parent_lic = _pom(blobs[PARENT_POM],
                        "com.sun.activation", "all", "1.2.1")
    if len(parent_lic) != 1 or parent_lic[0]["name"] != "EDL 1.0":
        raise AuditError("publisher parent declaration is not EDL 1.0")
    if (not parent_lic[0]["url"].startswith("http://www.eclipse.org/org/documents/edl-v10")
            and not parent_lic[0]["url"].startswith("https://www.eclipse.org/org/documents/edl-v10")):
        raise AuditError("parent licence publisher reference changed")

    upstream_tag_lic = blobs[TAG_LICENSE]
    tag_notice = blobs[TAG_NOTICE]
    tag_pom = blobs[TAG_API_POM]
    if (b"Redistribution and use in source and binary forms" not in upstream_tag_lic
            or b"Neither the name of the Eclipse Foundation" not in upstream_tag_lic
            or b"SPDX-License-Identifier: BSD-3-Clause" not in tag_notice
            or b"Eclipse Distribution License v. 1.0" not in tag_notice
            or b"SPDX-License-Identifier: BSD-3-Clause" not in tag_pom
            or b"*only* intended to be used" not in tag_pom):
        raise AuditError("exact tagged EDL / BSD three-clause supplier material changed")
    tag_parent, tag_lic = _child_pom(tag_pom)
    if tag_parent != PARENT_COORD or tag_lic:
        raise AuditError("exact source tag API POM parent/direct licence mismatch")
    if tag_pom != blobs[CHILD_POM]:
        raise AuditError("published child POM diverged from exact source release tag POM")

    jar_legal = _archive_legal_texts(blobs[CHILD_JAR])
    jar_lic = jar_legal[ARCHIVE_LICENSE]
    jar_notice = jar_legal[ARCHIVE_NOTICE]
    if jar_lic != upstream_tag_lic or jar_notice != tag_notice:
        raise AuditError("API JAR-embedded LICENSE/NOTICE differs from immutable source tag")
    return {
        "schemaVersion": 1,
        "status": "EXACT_ACTIVATION_API121_SOURCE_BYTES_MATCH_LEGAL_REVIEW_OPEN",
        "purl": PURL, "scope": "PUBLIC Gradle root/app buildEnvironment only",
        "mavenChildPOM": {"url": CHILD_POM, "sha256": _sha(blobs[CHILD_POM]),
                          "tagSourceByteParity": True},
        "mavenParentPOM": {"url": PARENT_POM, "sha256": _sha(blobs[PARENT_POM]),
                           "supplierDeclaredLicenceName": "EDL 1.0"},
        "mavenJar": {"url": CHILD_JAR, "sha256": _sha(blobs[CHILD_JAR]),
                     "byteSize": len(blobs[CHILD_JAR]),
                     "embeddedLicenseSha256": _sha(jar_lic),
                     "embeddedNoticeSha256": _sha(jar_notice),
                     "matchesLocalGradleBytes": True, "embeddedTextTagByteParity": True,
                     "embeddedNoticeTagByteParity": True},
        "upstreamTag": {"name": "1.2.1", "tagObject": ANNOTATED_TAG_SHA,
                         "commit": VERSION_COMMIT, "tagCryptographicallySigned": TAG_SIGNED,
                         "licenseGitBlobSha1": _git_blob_sha1(upstream_tag_lic),
                         "noticeGitBlobSha1": _git_blob_sha1(tag_notice),
                         "apiPomGitBlobSha1": _git_blob_sha1(tag_pom),
                         "licenseSha256": _sha(upstream_tag_lic),
                         "noticeSha256": _sha(tag_notice)},
        "organizationalAncestor": {"coordinate": COMPANY_ANCESTOR,
                                   "supplierMetadataOnly": True,
                                   "effectiveChildLicenseNotInferred": True},
        "declaredLicenseTextForReview": "EDL-1.0 (supplier tag notice states BSD-3-Clause)",
        "licenseOptionSelected": False, "sourceCopyrightComplianceVerified": False,
        "publisherSignatureVerified": False, "apkPackagingVerified": False,
        "productRuntimeInclusionVerified": False, "redistributionRightsVerified": False,
        "parentLicenseInheritanceVerified": False, "all42DirectPOMMetadataGapsOpen": True,
        "microsoftSDKBuildToolsExactRedistRights": "NOT_VERIFIED_SEPARATE_GATE",
        "noticeClosure": "NOT_VERIFIED", "licenseClosure": "NOT_VERIFIED",
        "sbomComplete": False, "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--review-queue", type=Path, required=True)
    p.add_argument("--android-runtime", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        result = audit(_read(a.inventory), _read(a.review_queue),
                       _read(a.android_runtime))
        a.output.write_text(json.dumps(result, ensure_ascii=True, sort_keys=True,
                                       indent=2) + "\n", encoding="utf-8")
    except (AuditError, KeyError, OSError, TypeError, ValueError) as exc:
        print("BLOCKED: exact Activation API 1.2.1 upstream/license evidence: " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({
        "purl": PURL, "status": result["status"],
        "jarSha256": result["mavenJar"]["sha256"],
        "licenseSha256": result["upstreamTag"]["licenseSha256"],
        "jarEmbeddedLicenseParity": result["mavenJar"]["embeddedTextTagByteParity"],
        "sourceTagPOMParity": result["mavenChildPOM"]["tagSourceByteParity"],
        "tagCryptographicallySigned": False,
        "releaseApproved": False,
        "licenseClosure": "NOT_VERIFIED",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
