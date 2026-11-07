#!/usr/bin/env python3
"""Four NEW direct-license-gap Gradle build-tool JARs vs official Maven bytes.

Strict build-only scope. Inputs are resolved PUBLIC CI Gradle module inventory
with SHA256 of *local* artifact bytes. Only the four reviewed Maven coordinates
below may be downloaded from the sole literal HTTPS origin, without redirects.
This is byte equality to an endpoint, NOT authenticated Maven publisher signing,
license clearance, full 147-module audit, SBOM or any runtime scanner acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib import error, request

TARGETS = (
    "pkg:maven/com.google.guava/failureaccess@1.0.2",
    "pkg:maven/com.google.protobuf/protobuf-java-util@3.25.5",
    "pkg:maven/com.google.jimfs/jimfs@1.1",
    "pkg:maven/com.google.auto.value/auto-value-annotations@1.6.2",
)
ORIGIN = "https://repo.maven.apache.org/maven2"
PURL = re.compile(r"pkg:maven/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_IN = 4_000_000
MAX_JAR = 16_000_000


class AuditError(ValueError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("unexpected Maven artifact redirect")


def choose(report: dict) -> list[dict]:
    if (report.get("status") != "PASS_WITH_GAPS"
            or report.get("inventoryCompleteness") != "PARTIAL"
            or report.get("licenseApproval") != "NOT_VERIFIED"
            or report.get("originVerified") is not False
            or report.get("sbomComplete") is not False
            or report.get("releaseApproved") is not False):
        raise AuditError("elevated or untrusted resolved build-tool inventory")
    modules = report.get("modules")
    counts = report.get("counts")
    if (not isinstance(modules, list) or not isinstance(counts, dict)
            or len(modules) != counts.get("modules")
            or not 4 <= len(modules) <= 512):
        raise AuditError("empty, unbounded or inconsistent Gradle module count")
    lookup = {}
    for module in modules:
        if not isinstance(module, dict) or not isinstance(module.get("purl"), str):
            raise AuditError("invalid Gradle plugin record")
        purl = module["purl"]
        if purl in lookup:
            raise AuditError("duplicate selected Maven coordinate")
        lookup[purl] = module
    chosen = []
    for purl in TARGETS:
        if purl not in lookup:
            raise AuditError("mandatory batch coordinate absent: " + purl)
        group, artifact, version = PURL.fullmatch(purl).groups()
        expected = artifact + "-" + version + ".jar"
        module = lookup[purl]
        # All four have genuinely missing direct child POM license names in
        # the pre-change PUBLIC Gradle graph. This is not a license grant,
        # even if an unverified parent later supplies a license label.
        if module.get("licenseMetadataState") != "POM_WITHOUT_DIRECT_LICENSE_NAME":
            raise AuditError("missing expected child-POM license metadata gap: " + purl)
        files = module.get("cachedFiles")
        if not isinstance(files, list) or len(files) > 32:
            raise AuditError("missing/oversized cached-file evidence")
        selected = [f for f in files if isinstance(f, dict) and f.get("filename") == expected]
        if len(selected) > 1:
            raise AuditError("ambiguous local JAR evidence: " + purl)
        variants = sorted(f.get("filename") for f in files
                          if isinstance(f, dict)
                          and isinstance(f.get("filename"), str)
                          and f["filename"].endswith(".jar")
                          and f["filename"] != expected)
        item = {"purl": purl, "filename": expected,
                "status": "LOCAL_STANDARD_JAR_NOT_CACHED",
                "localSha256": None, "localByteSize": None,
                "unreviewedJarVariants": variants,
                "directPomLicenseMetadata": module.get("licenseMetadataState"),
                "licenseApproved": False}
        if selected:
            f = selected[0]
            if (not isinstance(f.get("sha256"), str)
                    or not SHA256.fullmatch(f["sha256"])
                    or type(f.get("byteSize")) is not int
                    or not 0 < f["byteSize"] <= MAX_JAR
                    or f.get("sourceVerification") != "LOCAL_BYTES_ONLY"):
                raise AuditError("untrusted cached JAR size/digest or scope")
            item.update(status="PENDING_REMOTE", localSha256=f["sha256"],
                        localByteSize=f["byteSize"])
        chosen.append(item)
    return chosen


def retrieve(url: str) -> bytes | None:
    if not url.startswith(ORIGIN + "/"):
        raise AuditError("source URL is not allowlisted Maven Central")
    req = request.Request(url, headers={
        "User-Agent": "Embasic-E-Scanner-PUBLIC-Scoped-Build-Jar-Audit/1.0",
        "Accept": "application/java-archive,application/octet-stream",
    })
    try:
        with request.build_opener(NoRedirect).open(req, timeout=12) as response:
            if response.status != 200:
                raise AuditError("unexpected official artifact HTTP status")
            raw = response.read(MAX_JAR + 1)
            if len(raw) > MAX_JAR:
                raise AuditError("oversized official JAR")
            return raw
    except error.HTTPError as exc:
        if exc.code in (404, 410):
            return None
        raise AuditError("official source HTTP failure " + str(exc.code)) from exc
    except (error.URLError, TimeoutError, OSError) as exc:
        raise AuditError("official source transport unavailable") from exc


def audit(report: dict, fetcher=retrieve) -> dict:
    items = choose(report)
    results = []
    for item in items:
        group, artifact, version = PURL.fullmatch(item["purl"]).groups()
        url = (ORIGIN + "/" + group.replace(".", "/") + "/" + artifact +
               "/" + version + "/" + item["filename"])
        result = {**item, "officialSourceUrl": url, "officialSha256": None,
                  "publisherSignatureVerified": False}
        if item["status"] == "PENDING_REMOTE":
            try:
                blob = fetcher(url)
            except AuditError as exc:
                if any(x in str(exc) for x in ("redirect", "oversized",
                                               "allowlisted")):
                    raise
                result["status"] = "REMOTE_NOT_VERIFIED"
                result["failureType"] = str(exc)[:120]
            else:
                if blob is None:
                    result["status"] = "OFFICIAL_ARTIFACT_NOT_FOUND"
                else:
                    if len(blob) > MAX_JAR:
                        raise AuditError("oversized source bytes")
                    result["officialSha256"] = hashlib.sha256(blob).hexdigest()
                    if (result["officialSha256"] != result["localSha256"]
                            or len(blob) != result["localByteSize"]):
                        raise AuditError("OFFICIAL_BINARY_MISMATCH: " + item["purl"])
                    result["status"] = "SOURCE_BYTES_MATCH_LOCAL"
        results.append(result)
    matched = sum(x["status"] == "SOURCE_BYTES_MATCH_LOCAL" for x in results)
    return {
        "schemaVersion": 1,
        "scope": "FOUR distinct no-direct-license Gradle build-tool JARs; not all 147",
        "selectedArtifactCount": len(TARGETS), "sourceByteMatches": matched,
        "notSourceVerified": len(TARGETS) - matched,
        "status": "SOURCE_BYTE_PARITY_PASS" if matched == len(TARGETS)
                  else "PARTIAL_EVIDENCE_ONLY",
        "records": results,
        "publisherSignatureVerified": False,
        "originAttributionVerified": False,
        "licenseClosure": "NOT_VERIFIED",
        "noticeClosure": "NOT_VERIFIED",
        "sbomComplete": False, "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plugin-inventory", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        if (args.plugin_inventory.is_symlink() or
                not args.plugin_inventory.is_file() or
                args.plugin_inventory.stat().st_size > MAX_IN):
            raise AuditError("untrusted input file path/length")
        data = json.loads(args.plugin_inventory.read_text(encoding="utf-8"))
        result = audit(data)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (AuditError, UnicodeError, ValueError, TypeError, OSError) as exc:
        print("BLOCKED: scoped official Maven build-tool byte parity: " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"],
                      "sourceByteMatches": result["sourceByteMatches"],
                      "notSourceVerified": result["notSourceVerified"],
                      "publisherSignatureVerified": False,
                      "releaseApproved": False}, sort_keys=True))
    for row in result["records"]:
        print("BUILD_TOOL_CENTRAL_BYTE:", row["purl"], row["status"],
              row["officialSha256"] or "NO_REMOTE_HASH", row["officialSourceUrl"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
