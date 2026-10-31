#!/usr/bin/env python3
"""Fail-closed partial audit of actual Gradle root/app buildEnvironment output.

Not a complete plugin binary dependency SBOM. Records selected Maven versions,
not raw Gradle files or artifact licensing. No runtime import or network calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 3_000_000
EDGE = re.compile(
    r"^[ |]*[+\\]---\s+([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):"
    r"([^\s()]+)(?:\s+->\s+([^\s()]+))?"
)
EXPECTED_PLUGINS = {
    ("com.android.tools.build", "gradle"): "8.13.2",
    ("org.jetbrains.kotlin", "kotlin-gradle-plugin"): "2.3.21",
}


class AuditError(ValueError):
    pass


def audit(raw: bytes) -> dict:
    if not raw or len(raw) > MAX_BYTES:
        raise AuditError("missing or oversized buildEnvironment report")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise AuditError("invalid buildEnvironment encoding") from exc
    if ("BUILD SUCCESSFUL" not in text
            or "> Task :buildEnvironment" not in text
            or "> Task :app:buildEnvironment" not in text):
        raise AuditError("missing successful root/app plugin graph tasks")
    scopes: dict[str, dict[tuple[str, str], str]] = {"root": {}, "app": {}}
    active = ""
    unresolved = []
    for line in text.splitlines():
        if line.startswith("> Task :buildEnvironment"):
            active = "root"
            continue
        if line.startswith("> Task :app:buildEnvironment"):
            active = "app"
            continue
        if line.startswith("BUILD SUCCESSFUL"):
            active = ""
            continue
        if not active:
            continue
        if "FAILED" in line or "Could not resolve" in line:
            unresolved.append(active)
            continue
        edge = EDGE.match(line)
        if edge is None:
            continue
        group, name, requested, selected = edge.groups()
        version = selected or requested
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", version):
            raise AuditError("unbounded or malformed selected plugin version")
        key = (group, name)
        previous = scopes[active].get(key)
        if previous is not None and previous != version:
            raise AuditError("conflicting selected module version in plugin graph")
        scopes[active][key] = version
    if unresolved:
        raise AuditError("unresolved Gradle plugin/build-tool dependency")
    all_versions: dict[tuple[str, str], set[str]] = {}
    for scope in scopes.values():
        for key, ver in scope.items():
            all_versions.setdefault(key, set()).add(ver)
    for key, expected in EXPECTED_PLUGINS.items():
        if all_versions.get(key) != {expected}:
            raise AuditError("required Android/Kotlin plugin absent or not pinned")
    if not scopes["root"] and not scopes["app"]:
        raise AuditError("empty build-tool graph")
    groups = {
        scope: [
            {"purl": f"pkg:maven/{g}/{a}@{v}", "licenseApproved": False,
             "licenseEvidence": "NOT_VERIFIED", "binaryProvenance": "NOT_VERIFIED"}
            for (g, a), v in sorted(items.items())
        ]
        for scope, items in scopes.items()
    }
    return {
        "schemaVersion": 1,
        "scope": "PUBLIC-Android-Gradle-root+app-buildEnvironment",
        "status": "PASS",
        "root": groups["root"],
        "app": groups["app"],
        "moduleCounts": {key: len(v) for key, v in groups.items()},
        "reportSha256": hashlib.sha256(raw).hexdigest(),
        "inventoryCompleteness": "PARTIAL",
        "artifactHashesCovered": False,
        "pluginBinaryLicensesVerified": False,
        "releaseApproved": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args(argv)
    try:
        source = args.input
        if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_BYTES:
            raise AuditError("missing or unsafe plugin graph file")
        result = audit(source.read_bytes())
    except (AuditError, OSError) as exc:
        print("BLOCKED: Gradle plugin graph audit: " + str(exc), file=sys.stderr)
        return 2
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "moduleCounts": result["moduleCounts"],
        "reportSha256": result["reportSha256"],
        "releaseApproved": result["releaseApproved"],
        "scope": result["scope"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
