#!/usr/bin/env python3
"""PUBLIC Android build-tool plugin binary parity: two exact pinned JAR coordinates.

Strictly scope this probe to the *actual resolved* Gradle root plugin graph,
including local JAR SHA256 and byteSize previously measured by CI.
Queries two official fixed HTTPS distribution paths; no user URLs or redirects.
A mismatch is fail-closed, not a 'gap'. Missing/blocked/transport failures
are evidence gaps and remain NOT VERIFIED. License metadata is NOT a grant.
This is NOT signed provenance, all 147 dependencies, an SBOM or release gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib import error, request

EXPECTED = {
    "pkg:maven/com.android.tools.build/gradle@8.13.2":
        "https://dl.google.com/dl/android/maven2",
    "pkg:maven/org.jetbrains.kotlin/kotlin-gradle-plugin@2.3.21":
        "https://repo.maven.apache.org/maven2",
}
PURL = re.compile(r"pkg:maven/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_REPORT = 4_000_000
MAX_JAR = 64 * 1024 * 1024


class AuditError(ValueError):
    pass


class RefuseRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("unexpected official plugin artifact redirect")


def _selection(report: dict) -> list[dict]:
    if (report.get("status") != "PASS_WITH_GAPS"
            or report.get("inventoryCompleteness") != "PARTIAL"
            or report.get("licenseApproval") != "NOT_VERIFIED"
            or report.get("originVerified") is not False
            or report.get("releaseApproved") is not False
            or report.get("sbomComplete") is not False):
        raise AuditError("plugin inventory scope/provenance is untrusted")
    modules = report.get("modules")
    if not isinstance(modules, list) or not 2 <= len(modules) <= 512:
        raise AuditError("unbounded or empty resolved plugin inventory")
    by_purl: dict[str, dict] = {}
    for entry in modules:
        if not isinstance(entry, dict) or not isinstance(entry.get("purl"), str):
            raise AuditError("invalid plugin module")
        purl = entry["purl"]
        if purl in by_purl:
            raise AuditError("duplicate selected plugin purl")
        by_purl[purl] = entry
    if not set(EXPECTED).issubset(by_purl):
        raise AuditError("mandatory pinned plugin coordinates absent")
    selected = []
    for purl in sorted(EXPECTED):
        record = by_purl[purl]
        if not PURL.fullmatch(purl):
            raise AuditError("unsafe selected plugin purl")
        if not isinstance(record.get("cachedFiles"), list):
            raise AuditError("missing cached plugin file evidence")
        group, artifact, version = PURL.fullmatch(purl).groups()
        expected_name = f"{artifact}-{version}.jar"
        candidates = [x for x in record["cachedFiles"]
                      if isinstance(x, dict) and x.get("filename") == expected_name]
        if len(candidates) > 1:
            raise AuditError("ambiguous pinned plugin JAR hashes")
        if not candidates:
            selected.append({"purl": purl, "status": "LOCAL_JAR_NOT_PRESENT",
                             "filename": expected_name, "sha256": None,
                             "byteSize": None, "origin": EXPECTED[purl]})
            continue
        item = candidates[0]
        if (not isinstance(item.get("sha256"), str)
                or not SHA.fullmatch(item["sha256"])
                or type(item.get("byteSize")) is not int
                or not 0 < item["byteSize"] <= MAX_JAR
                or item.get("sourceVerification") != "LOCAL_BYTES_ONLY"):
            raise AuditError("unsafe locally-hashed plugin JAR evidence")
        selected.append({"purl": purl, "status": "PENDING_REMOTE",
                         "filename": expected_name, "sha256": item["sha256"],
                         "byteSize": item["byteSize"], "origin": EXPECTED[purl]})
    return selected


def _kotlin_gradle813_cache_variant(cache: Path | None) -> dict | None:
    """Inspect actual Gradle 8.13-8.14 Kotlin plugin variant, no classifiers guessed.

    Gradle 8.14.6 selects 'gradle813' according to JetBrains' supported
    plugin variants documentation. A POM-only cache entry is NOT binary proof.
    """
    if cache is None:
        return None
    if cache.is_symlink() or not cache.is_dir():
        raise AuditError("unsafe Gradle cache root for variant")
    base = cache / "org.jetbrains.kotlin" / "kotlin-gradle-plugin" / "2.3.21"
    if base.is_symlink():
        raise AuditError("symlinked Kotlin plugin cache")
    if not base.is_dir():
        return None
    filename = "kotlin-gradle-plugin-2.3.21-gradle813.jar"
    candidates = []
    dirs = list(base.iterdir())
    if len(dirs) > 200:
        raise AuditError("unbounded Kotlin plugin cache digest directories")
    for directory in dirs:
        if directory.is_symlink():
            raise AuditError("symlinked Kotlin plugin digest")
        if not directory.is_dir() or not re.fullmatch(r"[0-9a-f]{40}", directory.name):
            continue
        jar = directory / filename
        if jar.is_symlink():
            raise AuditError("symlinked Kotlin Gradle variant JAR")
        if jar.is_file():
            if jar.stat().st_size <= 0 or jar.stat().st_size > MAX_JAR:
                raise AuditError("empty/oversized Kotlin Gradle variant JAR")
            candidates.append(jar)
    if len(candidates) > 1:
        raise AuditError("ambiguous Kotlin Gradle variant JAR cache bytes")
    if not candidates:
        return None
    jar = candidates[0]
    sha = hashlib.sha256()
    with jar.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            sha.update(chunk)
    return {"filename": filename, "sha256": sha.hexdigest(),
            "byteSize": jar.stat().st_size, "status": "PENDING_REMOTE",
            "localEvidenceType": "CLASSIFIED_VARIANT_BYTES_FROM_GRADLE_CACHE"}


def fetch(url: str) -> bytes | None:
    if not any(url.startswith(origin + "/") for origin in EXPECTED.values()):
        raise AuditError("unapproved plugin repository host")
    req = request.Request(url, headers={
        "User-Agent": "Embasic-E-Scanner-PUBLIC-Pinned-Plugin-Integrity/1",
        "Accept": "application/java-archive,application/octet-stream",
    })
    try:
        with request.build_opener(RefuseRedirect).open(req, timeout=18) as stream:
            if stream.status != 200:
                raise AuditError("unexpected artifact response")
            body = stream.read(MAX_JAR + 1)
            if len(body) > MAX_JAR:
                raise AuditError("oversized upstream JAR")
            return body
    except error.HTTPError as exc:
        if exc.code in (404, 410):
            return None
        raise AuditError("upstream HTTP error " + str(exc.code)) from exc
    except (error.URLError, OSError, TimeoutError) as exc:
        raise AuditError("upstream network unavailable") from exc


def audit(report: dict, fetcher=fetch, cache: Path | None = None) -> dict:
    selected = _selection(report)
    results = []
    for item in selected:
        if (item["purl"] == "pkg:maven/org.jetbrains.kotlin/kotlin-gradle-plugin@2.3.21"
                and item["status"] == "LOCAL_JAR_NOT_PRESENT"):
            variant = _kotlin_gradle813_cache_variant(cache)
            if variant is not None:
                item.update(variant)
        group, artifact, version = PURL.fullmatch(item["purl"]).groups()
        path = ("/".join(group.split(".")) + f"/{artifact}/{version}/" +
                item["filename"])
        url = item["origin"] + "/" + path
        output = {
            "purl": item["purl"], "status": item["status"],
            "repositoryUrl": url, "localSha256": item["sha256"],
            "localByteSize": item["byteSize"], "remoteSha256": None,
            "localEvidenceType": item.get("localEvidenceType", "SCOPED_PLUGIN_GRAPH_BYTES"),
            "publisherSignatureVerified": False, "licenseApproved": False,
        }
        if item["status"] == "PENDING_REMOTE":
            try:
                body = fetcher(url)
            except AuditError as exc:
                # The source of failure is explicit; no forged pass.
                if any(s in str(exc) for s in ("redirect", "unapproved",
                                                "oversized")):
                    raise
                output["status"] = "REMOTE_NOT_VERIFIED"
                output["failureType"] = str(exc)[:120]
            else:
                if body is None:
                    output["status"] = "OFFICIAL_BINARY_NOT_FOUND"
                else:
                    if len(body) > MAX_JAR:
                        raise AuditError("oversized upstream JAR")
                    output["remoteSha256"] = hashlib.sha256(body).hexdigest()
                    if (output["remoteSha256"] != output["localSha256"]
                            or len(body) != output["localByteSize"]):
                        raise AuditError("PINNED_PLUGIN_OFFICIAL_BYTE_MISMATCH " + item["purl"])
                    output["status"] = "SOURCE_BYTES_MATCH_LOCAL"
        results.append(output)
    matches = sum(x["status"] == "SOURCE_BYTES_MATCH_LOCAL" for x in results)
    return {
        "schemaVersion": 1, "status":
            "SOURCE_BYTE_PARITY_PASS" if matches == 2 else "PARTIAL_EVIDENCE_ONLY",
        "scope": "2 pinned AGP/Kotlin Gradle build-tool plugin JARs, not 147 modules",
        "selectedPinnedPluginJarCount": 2, "sourceByteMatches": matches,
        "unverifiedPinnedPluginJars": 2 - matches,
        "records": results, "publisherSignatureVerified": False,
        "originAttributionVerified": False, "licenseClosure": "NOT_VERIFIED",
        "sbomComplete": False, "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plugin-inventory", type=Path, required=True)
    p.add_argument("--cache", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        inp = args.plugin_inventory
        if inp.is_symlink() or not inp.is_file() or inp.stat().st_size > MAX_REPORT:
            raise AuditError("missing/oversized plugin inventory")
        report = audit(json.loads(inp.read_text(encoding="utf-8")), cache=args.cache)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (AuditError, OSError, ValueError, UnicodeError, TypeError) as exc:
        print("BLOCKED: pinned plugin source-byte integrity: " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"], "byteMatches": report["sourceByteMatches"],
        "unverified": report["unverifiedPinnedPluginJars"],
        "publisherSignatureVerified": False, "licenseClosure": "NOT_VERIFIED",
        "releaseApproved": False}, sort_keys=True))
    for x in report["records"]:
        print("PLUGIN_SOURCE_BYTE:", x["purl"], x["status"], x["remoteSha256"] or "NONE",
              x["repositoryUrl"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
