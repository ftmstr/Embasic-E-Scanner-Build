#!/usr/bin/env python3
"""Hash selected actual Gradle-cache JARs from a separately resolved inventory.

Evidence of local bytes only; NOT Maven Central upstream integrity, provenance,
license rights, an Android APK contents inspection, or a release SBOM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

PURL = re.compile(r"pkg:maven/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)\Z")
MAX_JSON = 2_000_000
MAX_JAR = 64 * 1024 * 1024


class AuditError(ValueError):
    pass


def inventory(root: Path, cache: Path) -> dict:
    if root.is_symlink() or not root.is_file() or root.stat().st_size > MAX_JSON:
        raise AuditError("invalid resolved graph inventory input")
    obj = json.loads(root.read_text(encoding="utf-8"))
    if (obj.get("releaseApproved") is not False
            or obj.get("inventoryCompleteness") != "PARTIAL"
            or obj.get("graphAudit") != "PASS"
            or obj.get("noticeScopeCheck") != "PASS"):
        raise AuditError("unverified or unbounded graph inventory scope")
    if cache.is_symlink() or not cache.is_dir():
        raise AuditError("missing or symlinked Gradle module cache")
    seen: set[str] = set()
    artifacts: list[dict] = []
    for component in obj.get("runtimeComponents", []) + obj.get("testComponents", []):
        purl = component.get("purl", "")
        match = PURL.fullmatch(purl)
        if not match:
            raise AuditError("invalid Maven package URL")
        if purl in seen:
            continue
        seen.add(purl)
        group, name, version = match.groups()
        base = cache / group / name / version
        if base.is_symlink() or not base.is_dir():
            raise AuditError("resolved module JAR missing from Gradle cache")
        hits = list(base.glob("*/" + name + "-" + version + ".jar"))
        if len(hits) != 1:
            raise AuditError("missing or ambiguous cached Maven JAR")
        jar = hits[0]
        if (jar.is_symlink() or jar.parent.is_symlink()
                or not jar.is_file() or jar.stat().st_size == 0
                or jar.stat().st_size > MAX_JAR):
            raise AuditError("unsafe or oversized cached Maven JAR")
        digest = hashlib.sha256()
        with jar.open("rb") as reader:
            for chunk in iter(lambda: reader.read(65536), b""):
                digest.update(chunk)
        artifacts.append({
            "purl": purl,
            "sha256": digest.hexdigest(),
            "byteSize": jar.stat().st_size,
            "licenseApproved": False,
            "binaryProvenance": "NOT_VERIFIED",
        })
    if not seen:
        raise AuditError("empty scoped Gradle artifact inventory")
    return {
        "schemaVersion": 1,
        "scope": "Gradle-cached-JARs-from-Android-debug-and-JVM-test-graphs",
        "status": "PASS",
        "artifactCount": len(artifacts),
        "artifacts": sorted(artifacts, key=lambda x: x["purl"]),
        "sourceVerification": "LOCAL_SHA256_ONLY",
        "transitiveLicenseClosure": "NOT_VERIFIED",
        "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--cache", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args(argv)
    try:
        result = inventory(args.inventory, args.cache)
    except (AuditError, OSError, ValueError, KeyError, TypeError) as exc:
        print("BLOCKED: Gradle cached artifact hash audit: " + str(exc), file=sys.stderr)
        return 2
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
