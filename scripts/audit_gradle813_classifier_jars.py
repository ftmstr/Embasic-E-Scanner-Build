#!/usr/bin/env python3
"""PUBLIC Gradle 8.13 classifier JAR exact-byte comparison; NOT license clearance.

Closed-world: two named Kotlin 2.3.21 classifier artifacts only, from Maven
Central HTTPS with redirects disabled. Local SHA-256, pinned prior CI SHA-256,
official bytes and byte size must agree. This verifies endpoint byte parity
but NOT cryptographic publisher identity, legal license rights or an SBOM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib import error, request

ORIGIN = "https://repo.maven.apache.org/maven2"
TARGETS = {
    "pkg:maven/org.jetbrains.kotlin/fus-statistics-gradle-plugin@2.3.21": (
        "fus-statistics-gradle-plugin-2.3.21-gradle813.jar",
        "73379b384d9da66419b5f4d5c83de1a99dd7f195662bc45c39443859e63e18b2",
    ),
    "pkg:maven/org.jetbrains.kotlin/kotlin-gradle-plugin-api@2.3.21": (
        "kotlin-gradle-plugin-api-2.3.21-gradle813.jar",
        "ad58d2638ee041f6ce4e73e9782ebf528e18cf9003b1099aa7045ec958e3c195",
    ),
}
PURL = re.compile(r"pkg:maven/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_REPORT = 4_000_000
MAX_JAR = 64 * 1024 * 1024


class AuditError(ValueError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("Maven Central redirect is forbidden")


def select(report: dict) -> list[dict]:
    if (not isinstance(report, dict)
            or report.get("status") != "PASS_WITH_GAPS"
            or report.get("inventoryCompleteness") != "PARTIAL"
            or report.get("licenseApproval") != "NOT_VERIFIED"
            or report.get("originVerified") is not False
            or report.get("releaseApproved") is not False
            or report.get("sbomComplete") is not False):
        raise AuditError("elevated or untrusted Gradle inventory claims")
    modules, counts = report.get("modules"), report.get("counts")
    if (not isinstance(modules, list) or not isinstance(counts, dict)
            or len(modules) != counts.get("modules")
            or not 2 <= len(modules) <= 512):
        raise AuditError("invalid Gradle selected module count")
    by_purl = {}
    for module in modules:
        if not isinstance(module, dict) or not isinstance(module.get("purl"), str):
            raise AuditError("invalid resolved module record")
        purl = module["purl"]
        if not PURL.fullmatch(purl) or purl in by_purl:
            raise AuditError("unsafe or duplicated resolved Maven identity")
        by_purl[purl] = module
    if not set(TARGETS).issubset(by_purl):
        raise AuditError("missing required Kotlin gradle813 Maven coordinate")
    selected = []
    for purl, (filename, pinned_sha) in sorted(TARGETS.items()):
        group, artifact, version = PURL.fullmatch(purl).groups()
        if filename != artifact + "-" + version + "-gradle813.jar":
            raise AuditError("invalid allowlisted classifier filename")
        files = by_purl[purl].get("cachedFiles")
        if not isinstance(files, list) or len(files) > 64:
            raise AuditError("invalid or oversized Gradle cached file list")
        matched = [f for f in files if isinstance(f, dict) and f.get("filename") == filename]
        if len(matched) > 1:
            raise AuditError("ambiguous classified JAR local evidence")
        state = "LOCAL_CLASSIFIER_JAR_NOT_CACHED"
        local_sha, size = None, None
        if matched:
            f = matched[0]
            local_sha, size = f.get("sha256"), f.get("byteSize")
            if (not isinstance(local_sha, str) or not SHA256.fullmatch(local_sha)
                    or type(size) is not int or not 0 < size <= MAX_JAR
                    or f.get("classifier") != "gradle813"
                    or f.get("sourceVerification") != "LOCAL_BYTES_ONLY"
                    or f.get("binaryOrigin") != "NOT_VERIFIED"):
                raise AuditError("invalid cached classifier SHA, byte size or provenance")
            if local_sha != pinned_sha:
                raise AuditError("PINNED_CLASSIFIER_LOCAL_SHA_MISMATCH: " + purl)
            state = "PENDING_OFFICIAL_SOURCE"
        selected.append({
            "purl": purl, "filename": filename, "localSha256": local_sha,
            "pinnedSha256": pinned_sha, "localByteSize": size,
            "officialUrl": (ORIGIN + "/" + group.replace(".", "/") + "/" +
                            artifact + "/" + version + "/" + filename),
            "status": state,
        })
    return selected


def retrieve(url: str) -> bytes | None:
    # No arbitrary caller-provided path, host or URL is allowed.
    allowed = {
        ORIGIN + "/org/jetbrains/kotlin/" + PURL.fullmatch(purl).group(2) +
        "/2.3.21/" + filename
        for purl, (filename, _) in TARGETS.items()
    }
    if url not in allowed:
        raise AuditError("non-allowlisted Maven Central URL")
    req = request.Request(url, headers={
        "Accept": "application/java-archive,application/octet-stream",
        "User-Agent": "Embasic-E-Scanner-PUBLIC-Classified-JAR-Parity/1.0",
    })
    try:
        with request.build_opener(NoRedirect).open(req, timeout=18) as response:
            if response.status != 200:
                raise AuditError("unexpected official JAR HTTP status")
            raw = response.read(MAX_JAR + 1)
            if len(raw) > MAX_JAR:
                raise AuditError("oversized official classifier JAR")
            return raw
    except error.HTTPError as exc:
        if exc.code in (404, 410):
            return None
        raise AuditError("official JAR HTTP error " + str(exc.code)) from exc
    except (error.URLError, OSError, TimeoutError) as exc:
        raise AuditError("official Maven Central transport unavailable") from exc


def audit(report: dict, fetcher=retrieve) -> dict:
    records = []
    for selected in select(report):
        record = {**selected, "officialSha256": None, "officialByteSize": None,
                  "publisherSignatureVerified": False, "licenseApproved": False}
        if record["status"] == "PENDING_OFFICIAL_SOURCE":
            try:
                body = fetcher(record["officialUrl"])
            except AuditError as exc:
                # Network unavailability remains NOT VERIFIED, never an approval.
                # Redirects, URL manipulation and unbounded content fail closed.
                if any(word in str(exc) for word in ("redirect", "allowlisted", "oversized")):
                    raise
                record["status"] = "REMOTE_NOT_VERIFIED"
                record["reason"] = str(exc)[:120]
            else:
                if body is None:
                    record["status"] = "OFFICIAL_JAR_NOT_FOUND"
                else:
                    if not isinstance(body, bytes) or len(body) > MAX_JAR:
                        raise AuditError("invalid or oversized official JAR bytes")
                    record["officialSha256"] = hashlib.sha256(body).hexdigest()
                    record["officialByteSize"] = len(body)
                    if (record["officialSha256"] != record["pinnedSha256"]
                            or record["officialSha256"] != record["localSha256"]
                            or len(body) != record["localByteSize"]):
                        raise AuditError("OFFICIAL_CLASSIFIER_BYTE_MISMATCH: " + record["purl"])
                    record["status"] = "SOURCE_BYTES_MATCH_LOCAL"
        records.append(record)
    matches = sum(r["status"] == "SOURCE_BYTES_MATCH_LOCAL" for r in records)
    return {
        "schemaVersion": 1,
        "scope": "Two Kotlin Gradle 8.13 classifier build-tool JARs; not APK or Windows runtime",
        "status": "SOURCE_BYTE_PARITY_PASS" if matches == 2 else "BLOCKED_SOURCE_NOT_VERIFIED",
        "selectedClassifierCount": 2, "sourceByteMatches": matches,
        "notSourceVerified": 2 - matches, "records": records,
        "publisherSignatureVerified": False, "originAttributionVerified": False,
        "licenseClosure": "NOT_VERIFIED", "noticeClosure": "NOT_VERIFIED",
        "parentLicenseInheritanceVerified": False,
        "sbomComplete": False, "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-inventory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        inp = args.plugin_inventory
        if inp.is_symlink() or not inp.is_file() or not 0 < inp.stat().st_size <= MAX_REPORT:
            raise AuditError("invalid or oversized local Gradle inventory")
        result = audit(json.loads(inp.read_text(encoding="utf-8")), fetcher=retrieve)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (AuditError, UnicodeError, ValueError, TypeError, OSError) as exc:
        print("BLOCKED: classified Gradle JAR source parity: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"],
                      "byteMatches": result["sourceByteMatches"],
                      "notVerified": result["notSourceVerified"],
                      "publisherSignatureVerified": False, "releaseApproved": False},
                     sort_keys=True))
    for row in result["records"]:
        print("CLASSIFIER_OFFICIAL_BYTE:", row["purl"], row["status"],
              row["officialSha256"] or "NONE", row["officialUrl"])
    return 0 if result["status"] == "SOURCE_BYTE_PARITY_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
