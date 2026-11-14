#!/usr/bin/env python3
"""PUBLIC Android foundation: compare resolved local JAR hashes to official HTTPS repository bytes.

Exact BYTE parity is stronger than local SHA alone, but does NOT prove upstream
publisher signatures, transitive license rights, Android package contents or
release readiness. Only the previously verified small Android runtime/test JAR
inventory is accepted. No user-provided endpoints, URL redirects or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib import error, request

PURL = re.compile(r"pkg:maven/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_INPUT = 2_000_000
MAX_JAR = 8_000_000
MAX_COMPONENTS = 8
HOSTS = (
    "https://repo.maven.apache.org/maven2",
    "https://dl.google.com/dl/android/maven2",
)


class AuditError(ValueError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("unverified JAR origin redirect blocked")


def verify_inventory(data: dict) -> list[dict]:
    if (data.get("status") != "PASS" or data.get("releaseApproved") is not False
            or data.get("sourceVerification") != "LOCAL_SHA256_ONLY"
            or data.get("transitiveLicenseClosure") != "NOT_VERIFIED"):
        raise AuditError("unreviewed or elevated input inventory claims")
    rows = data.get("artifacts")
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_COMPONENTS:
        raise AuditError("empty or oversized resolved artifact scope")
    if data.get("artifactCount") != len(rows):
        raise AuditError("artifact count mismatch")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise AuditError("invalid Maven record")
        purl = row.get("purl")
        match = PURL.fullmatch(purl) if isinstance(purl, str) else None
        if not match:
            raise AuditError("unsafe Maven purl")
        for segment in match.groups():
            if segment in ("", ".", "..") or ".." in segment or segment.startswith("."):
                raise AuditError("unsafe Maven path segment")
        if purl in seen:
            raise AuditError("duplicate Maven artifact identity")
        seen.add(purl)
        if (not isinstance(row.get("sha256"), str)
                or not SHA256.fullmatch(row["sha256"]) or
                type(row.get("byteSize")) is not int or
                not 0 < row["byteSize"] <= MAX_JAR or
                row.get("licenseApproved") is not False or
                row.get("binaryProvenance") != "NOT_VERIFIED"):
            raise AuditError("unbounded hash, byte count or forged origin assertion")
    return sorted(rows, key=lambda row: row["purl"])


def official_fetch(url: str) -> bytes | None:
    if not any(url.startswith(origin + "/") for origin in HOSTS):
        raise AuditError("unapproved repository URL")
    req = request.Request(url, headers={
        "Accept": "application/java-archive,application/octet-stream",
        "User-Agent": "Embasic-E-Scanner-PUBLIC-Foundation-Source-Parity/1.0",
    })
    try:
        with request.build_opener(NoRedirect).open(req, timeout=12) as stream:
            if stream.status != 200:
                raise AuditError("unexpected JAR HTTP response")
            data = stream.read(MAX_JAR + 1)
            if len(data) > MAX_JAR:
                raise AuditError("remote JAR exceeds bounded byte limit")
            return data
    except error.HTTPError as exc:
        if exc.code in (404, 410):
            return None
        raise AuditError("upstream JAR HTTP error " + str(exc.code)) from exc
    except (error.URLError, TimeoutError, OSError) as exc:
        raise AuditError("upstream JAR transport unavailable") from exc


def audit(data: dict, fetch=official_fetch) -> dict:
    rows = verify_inventory(data)
    results = []
    for row in rows:
        group, artifact, version = PURL.fullmatch(row["purl"]).groups()
        path = "/".join(group.split(".")) + "/" + artifact + "/" + version + "/" + artifact + "-" + version + ".jar"
        result = {
            "purl": row["purl"], "localSha256": row["sha256"],
            "sourceSha256": None, "sourceUrl": None,
            "status": "OFFICIAL_SOURCE_UNAVAILABLE",
            "originSignatureVerified": False, "licenseApproved": False,
        }
        sources = []
        for origin in HOSTS:
            url = origin + "/" + path
            try:
                content = fetch(url)
            except AuditError as exc:
                # An accessible but tampered official source MUST NOT be silently
                # swapped for a different host. Transport failures stay visible.
                if "redirect" in str(exc) or "exceeds" in str(exc) or "unapproved" in str(exc):
                    raise
                sources.append({"source": origin, "status": "NOT_VERIFIED", "reason": str(exc)[:100]})
                continue
            if content is None:
                sources.append({"source": origin, "status": "NOT_FOUND"})
                continue
            if len(content) > MAX_JAR:
                raise AuditError("oversized official source byte content")
            remote_sha = hashlib.sha256(content).hexdigest()
            if len(content) != row["byteSize"] or remote_sha != row["sha256"]:
                raise AuditError("OFFICIAL_SOURCE_BYTE_MISMATCH for " + row["purl"])
            result.update({
                "sourceSha256": remote_sha, "sourceUrl": url,
                "status": "SOURCE_BYTES_MATCH_LOCAL", "sourceByteSize": len(content),
            })
            sources.append({"source": origin, "status": "MATCHED"})
            break
        result["sourceAttempts"] = sources
        results.append(result)
    matched = sum(r["status"] == "SOURCE_BYTES_MATCH_LOCAL" for r in results)
    return {
        "schemaVersion": 1,
        "scope": "Android debug runtime + JVM test JARs only (not Gradle plugins or APK)",
        "status": "SOURCE_BYTE_PARITY_PASS" if matched == len(results) else "BLOCKED_SOURCE_UNAVAILABLE",
        "sourceByteMatches": matched,
        "unverifiedSources": len(results) - matched,
        "artifacts": results,
        "publisherSignatureVerified": False,
        "originAttributionVerified": False,
        "licenseClosure": "NOT_VERIFIED",
        "sbomComplete": False,
        "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        path = args.inventory
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT:
            raise AuditError("invalid input inventory path/size")
        report = audit(json.loads(path.read_text(encoding="utf-8")))
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (AuditError, OSError, UnicodeError, TypeError, ValueError) as exc:
        print("BLOCKED: official source JAR byte comparison: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "matches": report["sourceByteMatches"],
                      "unverified": report["unverifiedSources"],
                      "publisherSignatureVerified": False, "releaseApproved": False}, sort_keys=True))
    return 0 if report["status"] == "SOURCE_BYTE_PARITY_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
