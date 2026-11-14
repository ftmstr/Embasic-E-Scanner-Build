#!/usr/bin/env python3
"""Exact FastInfoset 1.2.16 tagged Apache LICENSE, EDL NOTICE and JAR legal-text and Maven byte evidence.

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
from audit_activation_api121_exact_license import _local
from io import BytesIO
import zipfile
import stat

PURL = "pkg:maven/com.sun.xml.fastinfoset/FastInfoset@1.2.16"
PARENT = "com.sun.xml.fastinfoset:fastinfoset-project:1.2.16"
ANCESTOR = "org.eclipse.ee4j:project:1.0.5"
TAG = "1.2.16"
TAG_OBJECT = "d7f66b8461f13509f1f3d2763533bfa5a57570ad"
TAG_COMMIT = "df8b153272fd07a5e584c04a774afc8f4e67905c"
TAG_SIGNED = False
MAVEN = "https://repo.maven.apache.org/maven2/com/sun/xml/fastinfoset/"
CHILD_POM = MAVEN + "FastInfoset/1.2.16/FastInfoset-1.2.16.pom"
CHILD_JAR = MAVEN + "FastInfoset/1.2.16/FastInfoset-1.2.16.jar"
PARENT_POM = MAVEN + "fastinfoset-project/1.2.16/fastinfoset-project-1.2.16.pom"
TAG_ROOT = "https://raw.githubusercontent.com/eclipse-ee4j/jaxb-fi/" + TAG_COMMIT
TAG_LICENSE = TAG_ROOT + "/LICENSE"
TAG_NOTICE = TAG_ROOT + "/NOTICE.md"
TAG_FIME_LICENSE = TAG_ROOT + "/FIME/LICENSE-FIME.md"
ANCESTOR_POM = "https://repo.maven.apache.org/maven2/org/eclipse/ee4j/project/1.0.5/project-1.0.5.pom"
TAG_CHILD_POM = TAG_ROOT + "/code/fastinfoset/pom.xml"
TAG_PARENT_POM = TAG_ROOT + "/code/pom.xml"
TAG_BLOBS = {
    TAG_LICENSE: "b5c38428d3486cd7c4f8adb0f3824a39a9987372",
    TAG_NOTICE: "85121e7dd8aac65432eec604c6fe12cce454e79c",
    TAG_FIME_LICENSE: "c739f78bc05856bfbfe35a5b76f2d4e6242cea66",
    TAG_CHILD_POM: "4270e413e455d4a34912bce7ce6c34bab6636384",
    TAG_PARENT_POM: "ea6296b6dbee1ccb3ae54900399d57cdda24bacf",
}
LIMITS = {CHILD_POM: 65536, CHILD_JAR: 2_000_000,
          PARENT_POM: 65536, TAG_LICENSE: 16384, TAG_NOTICE: 32768, TAG_FIME_LICENSE: 8192, ANCESTOR_POM: 65536,
          TAG_CHILD_POM: 65536, TAG_PARENT_POM: 65536}
SHA = re.compile(r"[0-9a-f]{64}\Z")


def retrieve(url: str) -> bytes:
    lim = LIMITS.get(url)
    if lim is None:
        raise AuditError("nonallowlisted immutable FastInfoset source URL")
    req = request.Request(url, headers={
        "User-Agent": "Embasic-E-Scanner-PUBLIC-FastInfoset1216-Evidence/1",
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



def _jar_legal_texts(raw: bytes) -> dict[str, bytes]:
    """Fail-closed ZIP reader; exact FastInfoset resource contract LICENSE not LICENSE.md."""
    if not 0 < len(raw) <= LIMITS[CHILD_JAR]:
        raise AuditError("FastInfoset release JAR size exceeded")
    legal: dict[str, bytes] = {}
    required = {"META-INF/LICENSE", "META-INF/NOTICE.md"}
    seen: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            entries = archive.infolist()
            if not 0 < len(entries) <= 2048:
                raise AuditError("unbounded or empty FastInfoset archive entries")
            for entry in entries:
                name = entry.filename
                parts = name.rstrip("/").split("/")
                if (not name or name.startswith(("/", "\\"))
                        or "\\" in name or ":" in name or "//" in name
                        or any(part in ("", ".", "..") for part in parts)
                        or name.casefold() in seen
                        or stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFLNK):
                    raise AuditError("unsafe FastInfoset JAR path/duplicate/symlink")
                seen.add(name.casefold())
                total += entry.file_size
                if total > 20_000_000:
                    raise AuditError("FastInfoset archive decompression bound exceeded")
                if name in required:
                    if name in legal or not 0 < entry.file_size <= 32768:
                        raise AuditError("duplicate/empty/oversize FastInfoset JAR legal text")
                    legal[name] = archive.read(entry)
    except (zipfile.BadZipFile, RuntimeError, EOFError, OSError) as exc:
        raise AuditError("corrupt FastInfoset release JAR archive") from exc
    if set(legal) != required:
        raise AuditError("missing FastInfoset JAR LICENSE/NOTICE legal text")
    return legal


def _child_pom(raw: bytes) -> tuple[str, bool]:
    """The child inherits groupId/version from com.sun.xml.fastinfoset:fastinfoset-project."""
    from xml.etree import ElementTree as ET
    if not 0 < len(raw) <= 65536 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise AuditError("unsafe exact FastInfoset child POM XML")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AuditError("malformed exact FastInfoset child POM") from exc
    parent = root.find("./{*}parent")
    if parent is None:
        raise AuditError("missing exact FastInfoset parent")
    coordinate = ":".join((parent.findtext("./{*}" + k) or "").strip()
                          for k in ("groupId", "artifactId", "version"))
    group = (root.findtext("./{*}groupId") or "").strip()
    artifact = (root.findtext("./{*}artifactId") or "").strip()
    version = (root.findtext("./{*}version") or "").strip()
    if (coordinate != PARENT or group not in ("", "com.sun.xml.fastinfoset")
            or version not in ("", "1.2.16") or artifact != "FastInfoset"):
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
        raise AuditError("missing or duplicate exact selected FastInfoset module")
    mod = selected[0]
    scopes = mod.get("scopes")
    if (mod.get("licenseMetadataState") != "POM_WITHOUT_DIRECT_LICENSE_NAME"
            or mod.get("pomDeclaredLicenses") != []
            or not isinstance(scopes, list) or not 1 <= len(scopes) <= 2
            or len(scopes) != len(set(scopes))
            or not set(scopes).issubset({"root", "app"})):
        raise AuditError("FastInfoset POM direct gap or build-tool classpath scope drift")
    pom_cache = _local(mod, "FastInfoset-1.2.16.pom", 65536)
    jar_cache = _local(mod, "FastInfoset-1.2.16.jar", LIMITS[CHILD_JAR])

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
        raise AuditError("missing exact selected FastInfoset legal row")
    item = matches[0]
    names = item.get("complexParentLicenseMetadataNames")
    if (item.get("directPomState") != "POM_WITHOUT_DIRECT_LICENSE_NAME"
            or item.get("complexParentMetadataReviewRequired") is not True
            or not isinstance(names, list)
            or not {"Eclipse Distribution License - v 1.0",
                    "Eclipse Public License v. 2.0",
                    "GNU General Public License, version 2 with the GNU Classpath Exception"
                    }.issubset(set(names))):
        raise AuditError("FastInfoset child/legal ancestor supplier names changed")
    parent_rows = item.get("cachedParentPOMReviewEvidence")
    if not isinstance(parent_rows, list):
        raise AuditError("no cached FastInfoset parent evidence")
    p_matches = [p for p in parent_rows if isinstance(p, dict) and p.get("coordinate") == PARENT]
    a_matches = [p for p in parent_rows if isinstance(p, dict) and p.get("coordinate") == ANCESTOR]
    if len(p_matches) != 1 or len(a_matches) != 1:
        raise AuditError("immediate or EE4J ancestor evidence missing/duplicated")
    p, ancestor = p_matches[0], a_matches[0]
    if (p.get("status") != "PARENT_POM_METADATA_ONLY"
            or p.get("unverifiedSupplierLicenseNames") != ["Apache License, Version 2.0", "Eclipse Distribution License - v 1.0"]
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
            raise AuditError("FastInfoset newly selected in app runtime/test graph; legal review needed")

    urls = (CHILD_POM, CHILD_JAR, PARENT_POM, ANCESTOR_POM,
            TAG_LICENSE, TAG_NOTICE, TAG_FIME_LICENSE, TAG_CHILD_POM, TAG_PARENT_POM)
    blobs = {u:fetch(u) for u in urls}
    if any(not isinstance(blobs[u], bytes) or not 0 < len(blobs[u]) <= LIMITS[u]
           for u in urls):
        raise AuditError("unsafe exact upstream byte response")
    for u in TAG_BLOBS:
        if _git_blob_sha1(blobs[u]) != expected_blobs.get(u):
            raise AuditError("immutable version-tag source Git blob identity drift")
    for url, local in ((CHILD_POM, pom_cache), (CHILD_JAR, jar_cache)):
        if _sha(blobs[url]) != local["sha256"] or len(blobs[url]) != local["byteSize"]:
            raise AuditError("official FastInfoset Maven bytes do not match scoped cache")
    if _sha(blobs[PARENT_POM]) != p["localPOMSha256"]:
        raise AuditError("Maven parent POM does not match scoped cached SHA")
    if _sha(blobs[ANCESTOR_POM]) != ancestor["localPOMSha256"]:
        raise AuditError("Maven EE4J ancestor POM does not match scoped cached SHA")

    child_coord, has_direct_licenses = _child_pom(blobs[CHILD_POM])
    if child_coord != PARENT or has_direct_licenses:
        raise AuditError("child direct-licence gap changed unexpectedly")
    tag_child_parent, tag_direct_licenses = _child_pom(blobs[TAG_CHILD_POM])
    if tag_child_parent != PARENT or tag_direct_licenses:
        raise AuditError("tagged source runtime POM identity/drift")
    if blobs[CHILD_POM] != blobs[TAG_CHILD_POM]:
        raise AuditError("Maven child POM diverges from original exact commit source POM")
    _, lic = _pom(blobs[PARENT_POM], "com.sun.xml.fastinfoset", "fastinfoset-project", "1.2.16")
    required_parent_names = ["Apache License, Version 2.0", "Eclipse Distribution License - v 1.0"]
    if [x["name"] for x in lic] != required_parent_names:
        raise AuditError("exact Maven parent Apache/EDL supplier declaration drift")
    _, taglic = _pom(blobs[TAG_PARENT_POM], "com.sun.xml.fastinfoset", "fastinfoset-project", "1.2.16")
    if [x["name"] for x in taglic] != required_parent_names:
        raise AuditError("exact source parent Apache/EDL supplier text changed")
    if blobs[PARENT_POM] != blobs[TAG_PARENT_POM]:
        raise AuditError("Maven parent POM diverges from exact source parent bytes")
    _, ancestor_lic = _pom(blobs[ANCESTOR_POM], "org.eclipse.ee4j", "project", "1.0.5")
    expected_ancestor_names = ["Eclipse Public License v. 2.0",
                               "GNU General Public License, version 2 with the GNU Classpath Exception"]
    if [x["name"] for x in ancestor_lic] != expected_ancestor_names:
        raise AuditError("EE4J corporate parent GPL Classpath/EPL metadata changed; no child election")
    if not all(x.get("url") for x in ancestor_lic):
        raise AuditError("EE4J corporate licence references missing")
    licence = blobs[TAG_LICENSE]
    notice = blobs[TAG_NOTICE]
    fime_licence = blobs[TAG_FIME_LICENSE]
    if (b"Apache License" not in licence or b"Version 2.0" not in licence
            or b"Redistribution and use in source and binary forms" not in fime_licence
            or b"Neither the name of the Eclipse Foundation" not in fime_licence
            or b"Eclipse Distribution License v. 1.0" not in notice
            or b"SPDX-License-Identifier: BSD-3-Clause" not in notice
            or b"Oracle licenses this file to You under the Apache License, Version 2.0"
               not in blobs[TAG_CHILD_POM]
            or b"Apache License, Version 2.0" not in blobs[TAG_PARENT_POM]):
        raise AuditError("supplier Apache/EDL/FIME tagged source-text divergence")
    members = _jar_legal_texts(blobs[CHILD_JAR])
    if members["META-INF/LICENSE"] != licence or members["META-INF/NOTICE.md"] != notice:
        raise AuditError("JAR embedded Apache LICENSE/EDL NOTICE bytes not identical to exact tag")

    return {
        "schemaVersion": 1, "status": "EXACT_FASTINFOSET1216_MAVEN_TAG_LICENSE_NOTICE_PARITY_LEGAL_REVIEW_OPEN",
        "purl": PURL, "scope": "Android Gradle root/app buildEnvironment only",
        "tag": {"name": TAG, "commit": TAG_COMMIT, "tagObject": TAG_OBJECT,
                "tagCryptographicallySigned": False,
                "licenseBlobSha1": _git_blob_sha1(licence),
                "fimeLicenseBlobSha1": _git_blob_sha1(fime_licence),
                "fimeLicenseSha256": _sha(fime_licence),
                "noticeBlobSha1": _git_blob_sha1(notice),
                "runtimePomBlobSha1": _git_blob_sha1(blobs[TAG_CHILD_POM]),
                "parentPomBlobSha1": _git_blob_sha1(blobs[TAG_PARENT_POM]),
                "licenseSha256": _sha(licence), "noticeSha256": _sha(notice)},
        "mavenChildPOM": {"url": CHILD_POM, "sha256": _sha(blobs[CHILD_POM]),
                          "tagSourceByteParity": True},
        "mavenParentPOM": {"url": PARENT_POM, "sha256": _sha(blobs[PARENT_POM]),
                           "supplierMetadataOnly": True,
                           "licenseNames": required_parent_names, "tagSourceByteParity": True},
        "mavenAncestorPOM": {"url": ANCESTOR_POM, "sha256": _sha(blobs[ANCESTOR_POM]),
                             "supplierMetadataNamesOnly": expected_ancestor_names,
                             "effectiveChildLicenseNotInferred": True},
        "mavenJar": {"url": CHILD_JAR, "sha256": _sha(blobs[CHILD_JAR]),
                     "byteSize": len(blobs[CHILD_JAR]),
                     "matchesSelectedLocalGradleCache": True,
                     "embeddedLicenseSha256": _sha(members["META-INF/LICENSE"]),
                     "embeddedNoticeSha256": _sha(members["META-INF/NOTICE.md"]),
                     "embeddedLicenseNoticeTagByteParity": True},
        "organizationalAncestor": {"coordinate": ANCESTOR,
                                   "effectiveChildLicenseNotInferred": True},
        "sourceTextForReview": "root Apache-2.0, FIME BSD-3-Clause, project EDL NOTICE, parent Apache/EDL and EE4J EPL/GPL metadata, NOT a licence election",
        "fimeSourceApplicableToJarFilesVerified": False,
        "ancestorGPLClasspathApplicableToJarVerified": False,
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
        print("BLOCKED: FastInfoset 1.2.16 exact tagged Maven/legal-text evidence: "+str(exc),
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
