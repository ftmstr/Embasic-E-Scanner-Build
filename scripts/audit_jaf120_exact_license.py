#!/usr/bin/env python3
"""JAF 1.2.0 exact supplier licence-text and Maven JAR byte evidence.

PUBLIC Gradle BUILD-TOOL scope only. Proof of exact tagged source licence
bytes and official Maven repository byte parity is NOT a legal opinion,
licence election, publisher signature, APK file inventory, or release gate PASS.
"""
from __future__ import annotations

import argparse
from io import BytesIO
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from urllib import request, error
import xml.etree.ElementTree as ET
import zipfile

TARGET = "pkg:maven/com.sun.activation/javax.activation@1.2.0"
PARENT = "com.sun.activation:all:1.2.0"
ORIGIN = "https://repo.maven.apache.org/maven2"
PREFIX = ORIGIN + "/com/sun/activation/"
CHILD_POM = PREFIX + "javax.activation/1.2.0/javax.activation-1.2.0.pom"
PARENT_POM = PREFIX + "all/1.2.0/all-1.2.0.pom"
CHILD_JAR = PREFIX + "javax.activation/1.2.0/javax.activation-1.2.0.jar"
TAG_LICENSE = "https://raw.githubusercontent.com/javaee/activation/JAF-1_2_0/LICENSE.txt"
TAG_COMMIT = "8f8ec08d736983c839d31a7bd98d29594e508785"
TAG_LICENSE_GIT_BLOB = "5ad62c442b336861b5832b7a8197a507b7df61f0"
ALLOWED = {CHILD_POM: 65536, PARENT_POM: 65536,
           CHILD_JAR: 2_000_000, TAG_LICENSE: 131072}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_REPORT = 5_000_000
MAX_JAR_MEMBERS = 2048
MAX_JAR_UNCOMPRESSED = 20_000_000
LICENSE_MEMBER = "META-INF/LICENSE.txt"


class AuditError(ValueError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("unreviewed upstream redirect")


def retrieve(url: str) -> bytes:
    limit = ALLOWED.get(url)
    if limit is None:
        raise AuditError("nonallowlisted upstream licence/artefact URL")
    req = request.Request(url, headers={
        "User-Agent": "Embasic-E-Scanner-PUBLIC-JAF120-Evidence/1",
        "Accept": "application/octet-stream,application/xml,text/plain",
    })
    try:
        with request.build_opener(NoRedirect).open(req, timeout=12) as response:
            if response.status != 200:
                raise AuditError("unexpected upstream HTTP status")
            blob = response.read(limit + 1)
    except (error.HTTPError, error.URLError, TimeoutError, OSError) as exc:
        raise AuditError("upstream source unavailable: " + str(exc)[:120]) from exc
    if not 0 < len(blob) <= limit:
        raise AuditError("empty or oversized exact upstream bytes")
    return blob


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pom(raw: bytes, group: str, artifact: str, version: str) -> tuple[str | None, list[dict]]:
    if not 0 < len(raw) <= 65536 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise AuditError("unsafe exact Maven POM bytes")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AuditError("invalid exact Maven POM XML") from exc
    child_art = root.findtext("./{*}artifactId")
    child_group = root.findtext("./{*}groupId")
    child_version = root.findtext("./{*}version")
    parent = root.find("./{*}parent")
    parent_tuple = None
    if parent is not None:
        parent_tuple = tuple((parent.findtext("./{*}" + k) or "").strip()
                             for k in ("groupId", "artifactId", "version"))
    if (child_art != artifact or child_group not in (None, group)
            or child_version not in (None, version)
            or (child_group is None or child_version is None)
            and parent_tuple != (group, "all", version)):
        raise AuditError("upstream POM coordinate or parent mismatch")
    licenses = []
    for lic in root.findall("./{*}licenses/{*}license"):
        licenses.append({
            "name": (lic.findtext("./{*}name") or "").strip(),
            "url": (lic.findtext("./{*}url") or "").strip(),
            "comments": (lic.findtext("./{*}comments") or "").strip(),
        })
    return (":".join(parent_tuple) if parent_tuple else None), licenses


def _embedded_license(raw: bytes) -> bytes:
    if not 0 < len(raw) <= ALLOWED[CHILD_JAR]:
        raise AuditError("JAR archive size outside bounds")
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not 0 < len(infos) <= MAX_JAR_MEMBERS:
                raise AuditError("unbounded JAR archive entries")
            found = 0
            used: set[str] = set()
            total = 0
            data = None
            for info in infos:
                name = info.filename
                normalized = name.replace("\\", "/")
                if (not name or name.startswith(("/", "\\"))
                        or ":" in name or "\\" in name
                        or "//" in name or any(p in (".", "..", "")
                                               for p in name.strip("/").split("/"))
                        or normalized.casefold() in used
                        or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK):
                    raise AuditError("unsafe JAR member path/duplicate/symlink")
                used.add(normalized.casefold())
                total += info.file_size
                if total > MAX_JAR_UNCOMPRESSED:
                    raise AuditError("unbounded JAR uncompressed entries")
                if name == LICENSE_MEMBER:
                    found += 1
                    if info.file_size > 131072:
                        raise AuditError("embedded licence text oversized")
                    data = archive.read(info)
            if found != 1 or not data:
                raise AuditError("missing/ambiguous embedded JAF licence text")
            return data
    except (zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        raise AuditError("malformed JAR/embedded licence archive") from exc


def _git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") +
                        b"\0" + raw).hexdigest()


def _read(path: Path) -> dict:
    if (path.is_symlink() or not path.is_file()
            or not 0 < path.stat().st_size <= MAX_REPORT):
        raise AuditError("missing/unsafe selected PUBLIC CI input")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise AuditError("selected PUBLIC input not a JSON object")
    return data


def audit(inventory: dict, queue: dict, runtime: dict, fetch=retrieve,
          expected_tag_blob: str = TAG_LICENSE_GIT_BLOB) -> dict:
    if (inventory.get("status") != "PASS_WITH_GAPS"
            or inventory.get("licenseApproval") != "NOT_VERIFIED"
            or inventory.get("parentLicenseInheritanceVerified") is not False
            or inventory.get("originVerified") is not False
            or inventory.get("releaseApproved") is not False):
        raise AuditError("untrusted cached Gradle tool metadata status")
    modules = inventory.get("modules")
    if not isinstance(modules, list) or not modules:
        raise AuditError("missing selected Gradle modules")
    matches = [x for x in modules if isinstance(x, dict) and x.get("purl") == TARGET]
    if len(matches) != 1:
        raise AuditError("exact JAF module absent or duplicated")
    mod = matches[0]
    if (mod.get("licenseMetadataState") != "POM_WITHOUT_DIRECT_LICENSE_NAME"
            or mod.get("pomDeclaredLicenses") != []
            or sorted(mod.get("scopes", [])) != ["app", "root"]):
        # Actual observed scope could be only root/app; verify scope rather
        # than infer a product runtime from a plugin buildEnvironment graph.
        raise AuditError("JAF direct POM gap or build-tool scope changed")
    cached = mod.get("cachedFiles")
    if not isinstance(cached, list) or len(cached) > 24:
        raise AuditError("unsafe cached JAF archive listing")
    def local_file(name: str) -> dict:
        found = [x for x in cached if isinstance(x, dict)
                 and x.get("filename") == name]
        if len(found) != 1:
            raise AuditError("missing/duplicate selected JAF local byte evidence")
        f = found[0]
        if (not isinstance(f.get("sha256"), str)
                or not SHA256.fullmatch(f["sha256"])
                or type(f.get("byteSize")) is not int
                or not 0 < f["byteSize"] <= 2_000_000
                or f.get("sourceVerification") != "LOCAL_BYTES_ONLY"):
            raise AuditError("unverified/malformed local JAF cache metadata")
        return f
    local_pom = local_file("javax.activation-1.2.0.pom")
    local_jar = local_file("javax.activation-1.2.0.jar")

    if (queue.get("status") != "REVIEW_QUEUE_ONLY_LEGAL_NO_GO"
            or queue.get("licenseClosure") != "NOT_VERIFIED"
            or queue.get("releaseApproved") is not False
            or queue.get("parentLicenseInheritanceVerified") is not False
            or queue.get("microsoftSDKBuildToolsExactRedistRights") !=
                "NOT_VERIFIED_SEPARATE_GATE"):
        raise AuditError("selected POM legal queue gained false rights")
    items = queue.get("reviewQueue")
    if not isinstance(items, list) or len(items) != 42:
        raise AuditError("missing selected 42-child legal review boundary")
    selected = [x for x in items if isinstance(x, dict) and x.get("purl") == TARGET]
    if len(selected) != 1:
        raise AuditError("JAF legal reviewer row absent or repeated")
    item = selected[0]
    if (item.get("directPomState") != "POM_WITHOUT_DIRECT_LICENSE_NAME"
            or item.get("complexParentMetadataReviewRequired") is not True
            or "CDDL/GPLv2+CE" not in item.get("complexParentLicenseMetadataNames", [])
            or item.get("licenseApproved") is not False
            or item.get("redistributionRightsVerified") is not False):
        raise AuditError("JAF legal review evidence or rights tampered")
    cached_parents = item.get("cachedParentPOMReviewEvidence")
    if not isinstance(cached_parents, list) or not any(
            x.get("coordinate") == PARENT
            and x.get("status") == "PARENT_POM_METADATA_ONLY"
            and x.get("unverifiedSupplierLicenseNames") == ["CDDL/GPLv2+CE"]
            and isinstance(x.get("localPOMSha256"), str)
            and SHA256.fullmatch(x["localPOMSha256"])
            and x.get("licenseApproved") is False
            for x in cached_parents if isinstance(x, dict)):
        raise AuditError("missing JAF exact cached parent licence SHA/name")

    if (runtime.get("graphAudit") != "PASS"
            or runtime.get("scope") !=
                "android-:app:debugRuntimeClasspath+debugUnitTestRuntimeClasspath"
            or runtime.get("inventoryCompleteness") != "PARTIAL"
            or runtime.get("pluginClasspathCovered") is not False
            or runtime.get("apkPackagingVerified") is not False
            or runtime.get("licenseClosure") != "NOT_VERIFIED"
            or runtime.get("releaseApproved") is not False):
        raise AuditError("untrusted app/test scope or runtime claim")
    for key in ("runtimeComponents", "testComponents"):
        comp = runtime.get(key)
        if not isinstance(comp, list) or any(
                x.get("purl") == TARGET for x in comp if isinstance(x, dict)):
            raise AuditError("JAF was selected in app runtime/test scope; separate rights review")

    # Every upstream input is EXACT, bounded, HTTPS-only. If bytes differ,
    # that is a technical evidence failure, never a legal permission claim.
    evidence = {url: fetch(url) for url in
                (CHILD_POM, PARENT_POM, CHILD_JAR, TAG_LICENSE)}
    if any(not isinstance(blob, bytes) or not 0 < len(blob) <= ALLOWED[url]
           for url, blob in evidence.items()):
        raise AuditError("unverified/oversized upstream byte response")
    if (_sha(evidence[CHILD_POM]) != local_pom["sha256"]
            or len(evidence[CHILD_POM]) != local_pom["byteSize"]):
        raise AuditError("official child POM bytes differ from selected local cache")
    if (_sha(evidence[CHILD_JAR]) != local_jar["sha256"]
            or len(evidence[CHILD_JAR]) != local_jar["byteSize"]):
        raise AuditError("official JAF JAR bytes differ from selected local cache")
    pparent = next(x for x in cached_parents
                   if isinstance(x, dict) and x.get("coordinate") == PARENT)
    if _sha(evidence[PARENT_POM]) != pparent["localPOMSha256"]:
        raise AuditError("official parent POM bytes differ from cached parent SHA")
    parent, child_licenses = _pom(evidence[CHILD_POM],
                                 "com.sun.activation", "javax.activation", "1.2.0")
    if parent != PARENT or child_licenses:
        raise AuditError("child POM direct licence gap unexpectedly changed")
    _, parent_licenses = _pom(evidence[PARENT_POM],
                             "com.sun.activation", "all", "1.2.0")
    if len(parent_licenses) != 1 or parent_licenses[0]["name"] != "CDDL/GPLv2+CE":
        raise AuditError("unexpected exact parent POM supplier licence declaration")
    if (not "CDDL or GPL" in parent_licenses[0]["comments"]
            or not parent_licenses[0]["url"].endswith("/LICENSE.txt")):
        raise AuditError("parent POM dual option/legacy licence URL changed")

    tag_text = evidence[TAG_LICENSE]
    if (_git_blob_sha1(tag_text) != expected_tag_blob
            or b"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) Version 1.1"
               not in tag_text
            or b"CLASSPATH EXCEPTION" not in tag_text
            or b"The GNU General Public License (GPL) Version 2" not in tag_text):
        raise AuditError("tagged JAF 1.2.0 licence text/blob identity mismatch")
    jar_text = _embedded_license(evidence[CHILD_JAR])
    # A distinct embedded text must be reviewed; never call it equal.
    if jar_text != tag_text:
        raise AuditError("embedded JAF licence bytes differ from pinned release-tag licence")
    return {
        "schemaVersion": 1,
        "status": "EXACT_JAF120_SOURCE_BYTES_AND_LICENSE_TEXT_MATCH_REVIEW_OPEN",
        "purl": TARGET,
        "scope": "PUBLIC Gradle root/app buildEnvironment only, NOT APK contents",
        "mavenChildPOM": {"url": CHILD_POM, "sha256": _sha(evidence[CHILD_POM])},
        "mavenParentPOM": {"url": PARENT_POM, "sha256": _sha(evidence[PARENT_POM]),
                           "supplierLicenseName": "CDDL/GPLv2+CE",
                           "directChildLicenseDeclaration": False},
        "mavenJAR": {"url": CHILD_JAR, "sha256": _sha(evidence[CHILD_JAR]),
                     "byteSize": len(evidence[CHILD_JAR]),
                     "matchesLocalGradleCache": True},
        "tag": {"name": "JAF-1_2_0", "commit": TAG_COMMIT,
                "url": TAG_LICENSE, "licenseGitBlobSha1": _git_blob_sha1(tag_text),
                "licenseSha256": _sha(tag_text)},
        "embeddedLicense": {"path": LICENSE_MEMBER, "sha256": _sha(jar_text),
                            "matchesExactTaggedLicenseBytes": True},
        "dualLicenseOption": "POM_SUPPLIER_DECLARATION_ONLY_NOT_ELECTED",
        "classpathException": "SOURCE_TAG_TEXT_REVIEW_NEEDED_FILE_SCOPED",
        "distributionBoundary": "BUILD_TOOL_CLASSPATH_ONLY_APK_NOT_VERIFIED",
        "productRuntimeInclusionVerified": False,
        "parentLicenseInheritanceVerified": False,
        "licenseOptionSelected": False,
        "sourceCopyrightNoticeComplianceVerified": False,
        "publisherSignatureVerified": False,
        "microsoftSDKBuildToolsExactRedistRights": "NOT_VERIFIED_SEPARATE_GATE",
        "all42ChildLicenseReviewGapsOpen": True,
        "licenseClosure": "NOT_VERIFIED",
        "sbomComplete": False,
        "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-inventory", type=Path, required=True)
    parser.add_argument("--review-queue", type=Path, required=True)
    parser.add_argument("--android-runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = audit(_read(args.plugin_inventory), _read(args.review_queue),
                       _read(args.android_runtime))
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (AuditError, OSError, ValueError, TypeError, KeyError,
            zipfile.BadZipFile) as exc:
        print("BLOCKED: JAF 1.2.0 exact supplier licensing evidence: " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({
        "status": result["status"], "purl": result["purl"],
        "jarSha256": result["mavenJAR"]["sha256"],
        "tagLicenceSha256": result["tag"]["licenseSha256"],
        "releaseApproved": False, "licenseClosure": "NOT_VERIFIED",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
