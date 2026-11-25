#!/usr/bin/env python3
"""Exact JAXB API Commons Runtime 2.3.2 tagged LICENSE/NOTICE and Maven byte evidence.

The review is confined to PUBLIC Gradle build-tool selected metadata.
Byte equality never elects EDL/BSD rights, verifies publisher signatures,
establishes final APK/MSIX inclusion/exclusion, or approves distribution.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from urllib import error, request
from audit_jaf120_exact_license import AuditError, NoRedirect, _git_blob_sha1, _pom, _read, _sha
from audit_activation_api121_exact_license import _archive_legal_texts, _local

PURL = "pkg:maven/jakarta.xml.bind/jakarta.xml.bind-api@2.3.2"
PARENT = "jakarta.xml.bind:jakarta.xml.bind-api-parent:2.3.2"
ANCESTOR = "org.eclipse.ee4j:project:1.0.5"
TAG = "2.3.2"
TAG_OBJECT = "6e6292004b760313faf71973a3ccb578d73fe90a"
TAG_COMMIT = "18b50028fd7dbd1305c359cd5624b1cddb1724a8"
TAG_SIGNED = False
MAVEN = "https://repo.maven.apache.org/maven2/jakarta/xml/bind/"
CHILD_POM = MAVEN + "jakarta.xml.bind-api/2.3.2/jakarta.xml.bind-api-2.3.2.pom"
CHILD_JAR = MAVEN + "jakarta.xml.bind-api/2.3.2/jakarta.xml.bind-api-2.3.2.jar"
PARENT_POM = MAVEN + "jakarta.xml.bind-api-parent/2.3.2/jakarta.xml.bind-api-parent-2.3.2.pom"
TAG_ROOT = "https://raw.githubusercontent.com/jakartaee/jaxb-api/" + TAG_COMMIT
TAG_LICENSE = TAG_ROOT + "/LICENSE.md"
TAG_NOTICE = TAG_ROOT + "/NOTICE.md"
TAG_CHILD_POM = TAG_ROOT + "/jaxb-api/pom.xml"
TAG_PARENT_POM = TAG_ROOT + "/pom.xml"
TAG_BLOBS = {
    TAG_LICENSE: "6fb337cb014d5ae5d406194049b960982e307849",
    TAG_NOTICE: "5aac171d23ff9e49976751b7952759233af8a29e",
    TAG_CHILD_POM: "9415ef692cc29acaa647ced0fae057d8e57e3968",
    TAG_PARENT_POM: "979df40b6d322f23dc632bdd59c7f5121eb74fed",
}
LIMITS = {CHILD_POM: 65536, CHILD_JAR: 2_000_000,
          PARENT_POM: 65536, TAG_LICENSE: 16384, TAG_NOTICE: 32768,
          TAG_CHILD_POM: 65536, TAG_PARENT_POM: 65536}
SHA = re.compile(r"[0-9a-f]{64}\Z")


def retrieve(url: str) -> bytes:
    lim = LIMITS.get(url)
    if lim is None:
        raise AuditError("nonallowlisted immutable JAXB API source URL")
    req = request.Request(url, headers={
        "User-Agent": "Embasic-E-Scanner-PUBLIC-Istack308-Evidence/1",
        "Accept": "application/octet-stream,text/plain,application/xml",
    })
    try:
        with request.build_opener(NoRedirect).open(req, timeout=12) as response:
            if response.status != 200:
                raise AuditError("unexpected publisher/Maven HTTP status")
            body = response.read(lim + 1)
    except (error.HTTPError, error.URLError, OSError, TimeoutError) as exc:
        raise AuditError("pinned source unavailable: " + str(exc)[:120]) from exc
    if not 0 < len(body) <= lim:
        raise AuditError("empty or oversized exact upstream byte response")
    return body


def _child_pom(raw: bytes) -> tuple[str, bool]:
    """The child inherits groupId/version from jakarta.xml.bind:jakarta.xml.bind-api-parent."""
    from xml.etree import ElementTree as ET
    if not 0 < len(raw) <= 65536 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise AuditError("unsafe exact JAXB API child POM XML")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AuditError("malformed exact JAXB API child POM") from exc
    parent = root.find("./{*}parent")
    if parent is None:
        raise AuditError("missing exact JAXB API parent")
    coordinate = ":".join((parent.findtext("./{*}" + k) or "").strip()
                          for k in ("groupId", "artifactId", "version"))
    group = (root.findtext("./{*}groupId") or "").strip()
    artifact = (root.findtext("./{*}artifactId") or "").strip()
    version = (root.findtext("./{*}version") or "").strip()
    if (coordinate != PARENT or group not in ("", "jakarta.xml.bind")
            or version not in ("", "2.3.2") or artifact != "jakarta.xml.bind-api"):
        raise AuditError("child POM artifact/inherited parent version mismatch")
    return coordinate, bool(root.findall("./{*}licenses/{*}license"))


def audit(inventory: dict, review: dict, runtime: dict, fetch=retrieve,
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
        raise AuditError("untrusted scoped Gradle cache legal status")
    mods = inventory.get("modules")
    if not isinstance(mods, list) or not mods:
        raise AuditError("selected Gradle root/app graph missing")
    selected = [m for m in mods if isinstance(m, dict) and m.get("purl") == PURL]
    if len(selected) != 1:
        raise AuditError("missing or duplicate exact selected JAXB API module")
    mod = selected[0]
    scopes = mod.get("scopes")
    if (mod.get("licenseMetadataState") != "POM_WITHOUT_DIRECT_LICENSE_NAME"
            or mod.get("pomDeclaredLicenses") != []
            or not isinstance(scopes, list) or not 1 <= len(scopes) <= 2
            or len(scopes) != len(set(scopes))
            or not set(scopes).issubset({"root", "app"})):
        raise AuditError("JAXB API POM direct gap or build-tool classpath scope drift")
    pom_cache = _local(mod, "jakarta.xml.bind-api-2.3.2.pom", 65536)
    jar_cache = _local(mod, "jakarta.xml.bind-api-2.3.2.jar", LIMITS[CHILD_JAR])

    if (review.get("status") != "REVIEW_QUEUE_ONLY_LEGAL_NO_GO"
            or review.get("licenseClosure") != "NOT_VERIFIED"
            or review.get("releaseApproved") is not False
            or review.get("parentLicenseInheritanceVerified") is not False
            or review.get("microsoftSDKBuildToolsExactRedistRights") !=
                "NOT_VERIFIED_SEPARATE_GATE"):
        raise AuditError("legal review queue falsely approved release")
    rows = review.get("reviewQueue")
    if not isinstance(rows, list) or len(rows) != 42:
        raise AuditError("all 42 selected child gaps must remain present")
    seen = set()
    for row in rows:
        if (not isinstance(row, dict)
                or not isinstance(row.get("purl"), str)
                or row["purl"] in seen
                or row.get("licenseApproved") is not False
                or row.get("redistributionRightsVerified") is not False
                or row.get("parentLicenseInheritanceVerified") is not False
                or row.get("evidenceOnly") is not True):
            raise AuditError("duplicated or forged license approval in 42-row queue")
        seen.add(row["purl"])
    matches = [x for x in rows if x["purl"] == PURL]
    if len(matches) != 1:
        raise AuditError("missing exact selected JAXB API legal row")
    item = matches[0]
    names = item.get("complexParentLicenseMetadataNames")
    if (item.get("directPomState") != "POM_WITHOUT_DIRECT_LICENSE_NAME"
            or item.get("complexParentMetadataReviewRequired") is not True
            or not isinstance(names, list)
            or not {"Eclipse Distribution License - v 1.0",
                    "Eclipse Public License v. 2.0",
                    "GNU General Public License, version 2 with the GNU Classpath Exception"
                    }.issubset(set(names))):
        raise AuditError("JAXB API child/legal ancestor supplier names changed")
    parent_rows = item.get("cachedParentPOMReviewEvidence")
    if not isinstance(parent_rows, list):
        raise AuditError("no cached JAXB API parent evidence")
    p_matches = [p for p in parent_rows if isinstance(p, dict) and p.get("coordinate") == PARENT]
    a_matches = [p for p in parent_rows if isinstance(p, dict) and p.get("coordinate") == ANCESTOR]
    if len(p_matches) != 1 or len(a_matches) != 1:
        raise AuditError("immediate or EE4J ancestor evidence missing/duplicated")
    p, ancestor = p_matches[0], a_matches[0]
    if (p.get("status") != "PARENT_POM_METADATA_ONLY"
            or p.get("unverifiedSupplierLicenseNames") != ["Eclipse Distribution License - v 1.0"]
            or p.get("licenseApproved") is not False
            or not isinstance(p.get("localPOMSha256"), str)
            or not SHA.fullmatch(p["localPOMSha256"])
            or ancestor.get("status") != "PARENT_POM_METADATA_ONLY"
            or ancestor.get("licenseApproved") is not False
            or not isinstance(ancestor.get("localPOMSha256"), str)
            or not SHA.fullmatch(ancestor["localPOMSha256"])):
        raise AuditError("invalid parent POM hash/status or forged legal rights")

    if (runtime.get("graphAudit") != "PASS"
            or runtime.get("scope") !=
                "android-:app:debugRuntimeClasspath+debugUnitTestRuntimeClasspath"
            or runtime.get("inventoryCompleteness") != "PARTIAL"
            or runtime.get("pluginClasspathCovered") is not False
            or runtime.get("apkPackagingVerified") is not False
            or runtime.get("licenseClosure") != "NOT_VERIFIED"
            or runtime.get("releaseApproved") is not False):
        raise AuditError("Android partial runtime graph scope/rights drift")
    for k in ("runtimeComponents", "testComponents"):
        comps = runtime.get(k)
        if not isinstance(comps, list) or any(
                isinstance(v, dict) and v.get("purl") == PURL for v in comps):
            raise AuditError("JAXB API newly selected in app runtime/test graph; legal review needed")

    urls = (CHILD_POM, CHILD_JAR, PARENT_POM,
            TAG_LICENSE, TAG_NOTICE, TAG_CHILD_POM, TAG_PARENT_POM)
    blobs = {u:fetch(u) for u in urls}
    if any(not isinstance(blobs[u], bytes) or not 0 < len(blobs[u]) <= LIMITS[u]
           for u in urls):
        raise AuditError("unsafe exact upstream byte response")
    for u in TAG_BLOBS:
        if _git_blob_sha1(blobs[u]) != expected_blobs.get(u):
            raise AuditError("immutable version-tag source Git blob identity drift")
    for url, local in ((CHILD_POM, pom_cache), (CHILD_JAR, jar_cache)):
        if _sha(blobs[url]) != local["sha256"] or len(blobs[url]) != local["byteSize"]:
            raise AuditError("official JAXB API Maven bytes do not match scoped cache")
    if _sha(blobs[PARENT_POM]) != p["localPOMSha256"]:
        raise AuditError("Maven parent POM does not match scoped cached SHA")

    child_coord, has_direct_licenses = _child_pom(blobs[CHILD_POM])
    if child_coord != PARENT or has_direct_licenses:
        raise AuditError("child direct-licence gap changed unexpectedly")
    tag_child_parent, tag_direct_licenses = _child_pom(blobs[TAG_CHILD_POM])
    if tag_child_parent != PARENT or tag_direct_licenses:
        raise AuditError("tagged source runtime POM identity/drift")
    if blobs[CHILD_POM] != blobs[TAG_CHILD_POM]:
        raise AuditError("Maven child POM diverges from original exact commit source POM")
    _, lic = _pom(blobs[PARENT_POM], "jakarta.xml.bind", "jakarta.xml.bind-api-parent", "2.3.2")
    if (len(lic) != 1 or lic[0]["name"] != "Eclipse Distribution License - v 1.0"
            or not lic[0]["url"].endswith("/edl-v10.php")):
        raise AuditError("exact Maven parent EDL declaration drift")
    _, taglic = _pom(blobs[TAG_PARENT_POM], "jakarta.xml.bind", "jakarta.xml.bind-api-parent", "2.3.2")
    if len(taglic) != 1 or taglic[0]["name"] != lic[0]["name"]:
        raise AuditError("exact source parent POM declared EDL version mismatch")
    if blobs[PARENT_POM] != blobs[TAG_PARENT_POM]:
        raise AuditError("Maven parent POM diverges from exact source parent bytes")
    licence = blobs[TAG_LICENSE]
    notice = blobs[TAG_NOTICE]
    if (b"Redistribution and use in source and binary forms" not in licence
            or b"Neither the name of the Eclipse Foundation" not in licence
            or b"Eclipse Distribution License v. 1.0" not in notice
            or b"SPDX-License-Identifier: BSD-3-Clause" not in notice
            or b"SPDX-License-Identifier: BSD-3-Clause" not in blobs[TAG_CHILD_POM]):
        raise AuditError("version-pinned supplier EDL/BSD source-text metadata changed")
    members = _archive_legal_texts(blobs[CHILD_JAR])
    if members["META-INF/LICENSE.md"] != licence or members["META-INF/NOTICE.md"] != notice:
        raise AuditError("JAR embedded legal-text bytes not equal to exact tagged source files")

    return {
        "schemaVersion": 1, "status": "EXACT_JAXBAPI232_MAVEN_TAG_LICENSE_NOTICE_PARITY_LEGAL_REVIEW_OPEN",
        "purl": PURL, "scope": "Android Gradle root/app buildEnvironment only",
        "tag": {"name": TAG, "commit": TAG_COMMIT, "tagObject": TAG_OBJECT,
                "tagCryptographicallySigned": False,
                "licenseBlobSha1": _git_blob_sha1(licence),
                "noticeBlobSha1": _git_blob_sha1(notice),
                "runtimePomBlobSha1": _git_blob_sha1(blobs[TAG_CHILD_POM]),
                "parentPomBlobSha1": _git_blob_sha1(blobs[TAG_PARENT_POM]),
                "licenseSha256": _sha(licence), "noticeSha256": _sha(notice)},
        "mavenChildPOM": {"url": CHILD_POM, "sha256": _sha(blobs[CHILD_POM]),
                          "tagSourceByteParity": True},
        "mavenParentPOM": {"url": PARENT_POM, "sha256": _sha(blobs[PARENT_POM]),
                           "supplierMetadataOnly": True,
                           "licenseName": lic[0]["name"], "tagSourceByteParity": True},
        "mavenJar": {"url": CHILD_JAR, "sha256": _sha(blobs[CHILD_JAR]),
                     "byteSize": len(blobs[CHILD_JAR]),
                     "matchesSelectedLocalGradleCache": True,
                     "embeddedLicenseSha256": _sha(members["META-INF/LICENSE.md"]),
                     "embeddedNoticeSha256": _sha(members["META-INF/NOTICE.md"]),
                     "embeddedLicenseNoticeTagByteParity": True},
        "organizationalAncestor": {"coordinate": ANCESTOR,
                                   "effectiveChildLicenseNotInferred": True},
        "sourceTextForReview": "EDL-1.0 / BSD-3-Clause supplier source, NOT a legal approval",
        "licenseOptionSelected": False,
        "publisherSignatureVerified": False, "apkPackagingVerified": False,
        "productRuntimeInclusionVerified": False,
        "sourceCopyrightComplianceVerified": False,
        "redistributionRightsVerified": False, "parentLicenseInheritanceVerified": False,
        "all42ChildPOMReviewGapsOpen": True, "sbomComplete": False,
        "noticeClosure": "NOT_VERIFIED", "licenseClosure": "NOT_VERIFIED",
        "microsoftSDKBuildToolsExactRedistRights": "NOT_VERIFIED_SEPARATE_GATE",
        "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--review-queue", type=Path, required=True)
    p.add_argument("--android-runtime", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        evidence = audit(_read(args.inventory), _read(args.review_queue),
                         _read(args.android_runtime))
        args.output.write_text(json.dumps(evidence, sort_keys=True, indent=2)+"\n", encoding="utf-8")
    except (AuditError, KeyError, OSError, TypeError, ValueError) as exc:
        print("BLOCKED: JAXB API 2.3.2 exact tagged Maven/legal-text evidence: "+str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({
        "status": evidence["status"], "purl": PURL,
        "mavenJarSha256": evidence["mavenJar"]["sha256"],
        "licenseSha256": evidence["tag"]["licenseSha256"],
        "noticeSha256": evidence["tag"]["noticeSha256"],
        "taggedLegalTextByteParity": True,
        "releaseApproved": False, "licenseClosure": "NOT_VERIFIED",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
