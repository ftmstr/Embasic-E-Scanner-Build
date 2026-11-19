#!/usr/bin/env python3
"""Research-only HTTPS POM discovery for actual PUBLIC Gradle cache gaps.

Inputs are the CI-generated scoped plugin artifact inventory, not user URLs.
Only POM_NOT_CACHED selected modules and explicitly missing ancestor POMs are
fetched, from two exact official Maven distribution hosts.

An HTTPS POM and its locally computed SHA256 are NOT signed provenance,
a publisher identity attestation, a JAR binary hash match or a license grant.
Do not synthesize effective/parent license inheritance or release approval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib import error, request
import xml.etree.ElementTree as ET

MAX_JSON_BYTES = 3_000_000
MAX_POM_BYTES = 1_048_576
MAX_TARGETS = 32
MAX_FETCHES = MAX_TARGETS * 2
PURL = re.compile(r"pkg:maven/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)\Z")
COORD = re.compile(r"([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)\Z")
HOSTS = (
    "https://repo.maven.apache.org/maven2",
    "https://dl.google.com/dl/android/maven2",
)


class AuditError(ValueError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("POM source attempted a redirect; origin not verified")


def validate_coordinate(group: str, artifact: str, version: str) -> None:
    for val in (group, artifact, version):
        if not val or val in (".", "..") or ".." in val or val.startswith("."):
            raise AuditError("unbounded Maven segment")


def targets_from_report(report: dict) -> list[dict]:
    if (report.get("status") != "PASS_WITH_GAPS"
            or report.get("releaseApproved") is not False
            or report.get("originVerified") is not False
            or report.get("parentLicenseInheritanceVerified") is not False
            or report.get("inventoryCompleteness") != "PARTIAL"
            or report.get("licenseApproval") != "NOT_VERIFIED"):
        raise AuditError("untrusted upstream plugin report release/provenance")
    modules = report.get("modules")
    if not isinstance(modules, list) or not modules or len(modules) > 512:
        raise AuditError("empty or unbounded plugin report")
    candidates: dict[str, set[str]] = {}
    for mod in modules:
        if not isinstance(mod, dict):
            raise AuditError("unexpected module entry")
        purl = mod.get("purl", "")
        m = PURL.fullmatch(purl) if isinstance(purl, str) else None
        if not m:
            raise AuditError("unsafe Maven package URL")
        validate_coordinate(*m.groups())
        if mod.get("licenseMetadataState") == "POM_NOT_CACHED":
            candidates.setdefault(purl, set()).add("SELECTED_POM_NOT_CACHED")
        for chain in mod.get("parentPomEvidence", []):
            if not isinstance(chain, list) or len(chain) > 6:
                raise AuditError("unbounded POM chain")
            for ancestor in chain:
                if ancestor.get("status") != "PARENT_POM_NOT_CACHED":
                    continue
                coord = ancestor.get("coordinate", "")
                match = COORD.fullmatch(coord) if isinstance(coord, str) else None
                if match is None:
                    raise AuditError("unsafe missing POM parent")
                validate_coordinate(*match.groups())
                group, artifact, version = match.groups()
                target = f"pkg:maven/{group}/{artifact}@{version}"
                candidates.setdefault(target, set()).add("MISSING_PARENT_POM")
    if not candidates or len(candidates) > MAX_TARGETS:
        raise AuditError("missing or excessive missing Maven POM targets")
    return [{"purl": purl, "reasons": sorted(reasons)}
            for purl, reasons in sorted(candidates.items())]


def _pom_info(raw: bytes, group: str, artifact: str, version: str) -> dict:
    if not raw or len(raw) > MAX_POM_BYTES or b"<!DOCTYPE" in raw.upper():
        raise AuditError("unsafe remote POM XML length or DTD")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise AuditError("malformed remote Maven POM XML") from exc
    direct_artifact = (root.findtext("{*}artifactId") or "").strip()
    direct_version = (root.findtext("{*}version") or "").strip()
    direct_group = (root.findtext("{*}groupId") or "").strip()
    if (direct_artifact != artifact or
            (direct_version and direct_version != version) or
            (direct_group and direct_group != group)):
        raise AuditError("remote POM direct coordinates mismatch")
    # Research only: do not inherit from parent and do not evaluate license URLs.
    licenses = []
    for lic in root.findall("./{*}licenses/{*}license"):
        name = (lic.findtext("{*}name") or "").strip()[:256]
        link = (lic.findtext("{*}url") or "").strip()[:512]
        if name:
            licenses.append({"name": name, "url": link,
                             "evidence": "UNVERIFIED_REMOTE_POM_DECLARATION"})
    parent = root.find("{*}parent")
    parent_coord = None
    if parent is not None:
        vals = [(parent.findtext("{*}" + k) or "").strip()
                for k in ("groupId", "artifactId", "version")]
        if all(vals) and COORD.fullmatch(":".join(vals)):
            validate_coordinate(*vals)
            parent_coord = ":".join(vals)
    return {"supplierDeclaredLicenses": licenses, "unverifiedParent": parent_coord}


def https_fetch(url: str) -> bytes | None:
    """Fetch only known literal HTTPS origins; disallow cross-host redirects."""
    if not any(url.startswith(base + "/") for base in HOSTS):
        raise AuditError("non-allowlisted remote POM URL")
    opener = request.build_opener(NoRedirect)
    try:
        req = request.Request(url, headers={
            "User-Agent": "Embasic-E-Scanner-PUBLIC-Provenance-Preflight/1.0",
            "Accept": "application/xml,text/xml",
        })
        with opener.open(req, timeout=8) as stream:
            if stream.status != 200:
                raise AuditError("unexpected POM HTTP status")
            body = stream.read(MAX_POM_BYTES + 1)
            if len(body) > MAX_POM_BYTES:
                raise AuditError("oversized remote POM")
            return body
    except error.HTTPError as exc:
        if exc.code in (404, 410):
            return None
        raise AuditError("remote POM HTTP failure " + str(exc.code)) from exc
    except (error.URLError, TimeoutError, OSError) as exc:
        raise AuditError("remote POM transport unavailable") from exc


def audit(report: dict, fetch=https_fetch) -> dict:
    targets = targets_from_report(report)
    output = []
    for target in targets:
        match = PURL.fullmatch(target["purl"])
        group, artifact, version = match.groups()
        rel = "/".join(group.split(".")) + "/" + artifact + "/" + version + "/" + artifact + "-" + version + ".pom"
        record = {
            "purl": target["purl"], "reasons": target["reasons"],
            "status": "UPSTREAM_POM_UNAVAILABLE", "sha256": None,
            "byteSize": None, "officialRepositoryUrl": None,
            "supplierDeclaredLicenses": [], "unverifiedParent": None,
            "licenseApproved": False, "publisherSignatureVerified": False,
        }
        attempts = []
        for host in HOSTS:
            url = host + "/" + rel
            try:
                body = fetch(url)
                if body is None:
                    attempts.append({"host": host, "status": "NOT_FOUND"})
                    continue
                info = _pom_info(body, group, artifact, version)
                record.update(info)
                record.update({"status": "UPSTREAM_POM_METADATA_RETRIEVED",
                               "sha256": hashlib.sha256(body).hexdigest(),
                               "byteSize": len(body), "officialRepositoryUrl": url})
                attempts.append({"host": host, "status": "FETCHED"})
                break
            except AuditError as exc:
                # Do not conceal tampered/mismatched content or security policy
                # violation by silently accepting a response from another host.
                msg = str(exc)
                if any(k in msg for k in ("mismatch", "unsafe", "oversized",
                                          "redirect", "unbounded")):
                    raise
                attempts.append({"host": host, "status": "NOT_VERIFIED",
                                 "error": msg[:120]})
        record["attempts"] = attempts
        output.append(record)
    successes = sum(x["status"] == "UPSTREAM_POM_METADATA_RETRIEVED" for x in output)
    return {
        "schemaVersion": 1,
        "status": "PARTIAL_EVIDENCE_ONLY",
        "scope": "PUBLIC-Gradle-selected-missing-POM-and-parent-only",
        "targets": len(output), "remotePomMetadataRetrieved": successes,
        "stillUnretrieved": len(output) - successes,
        "records": output,
        "originalDirectLicenseGaps": len(report["missingDirectLicenseEvidence"]),
        "originVerified": False, "artifactBinaryVerified": False,
        "parentLicenseInheritanceVerified": False,
        "licenseClosure": "NOT_VERIFIED", "sbomComplete": False,
        "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plugin-report", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        path = args.plugin_report
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
            raise AuditError("invalid plugin inventory file")
        report = json.loads(path.read_text(encoding="utf-8"))
        result = audit(report)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (AuditError, ValueError, TypeError, KeyError, OSError) as exc:
        print("BLOCKED: bounded remote POM research audit: " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({
        "status": result["status"], "targets": result["targets"],
        "remotePomMetadataRetrieved": result["remotePomMetadataRetrieved"],
        "stillUnretrieved": result["stillUnretrieved"],
        "originVerified": False, "licenseClosure": "NOT_VERIFIED",
        "releaseApproved": False,
    }, sort_keys=True))
    for item in result["records"]:
        print("REMOTE_POM_RESEARCH:", item["purl"], item["status"],
              item["sha256"] or "NO_SHA", "parent", item["unverifiedParent"] or "NONE",
              "directNames", ",".join(x["name"] for x in item["supplierDeclaredLicenses"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
