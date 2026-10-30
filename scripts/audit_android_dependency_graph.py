#!/usr/bin/env python3
"""Fail-closed, scoped Android Gradle graph audit. NOT a release SBOM.

Reads the output of *two resolved* Gradle :app:dependencies configurations.
No network, arbitrary paths, secrets, or license approvals. Never claims a
complete Gradle plugin/toolchain graph, a verified binary origin or a release.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 2_000_000
NODE = re.compile(
    r"^[ |]*[+\\]---\s+([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):"
    r"([^\s()]+)(?:\s+->\s+([^\s()]+))?"
)
TEST_ALLOWED = {
    ("junit", "junit"): "4.13.2",
    ("org.hamcrest", "hamcrest-core"): "1.3",
}
TEST_LICENSE_METADATA = {
    ("junit", "junit"): "EPL-1.0 (supplier POM; test-only boundary)",
    ("org.hamcrest", "hamcrest-core"): "New BSD (supplier POM; test-only boundary)",
}


class AuditError(ValueError):
    pass


def read_report(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise AuditError("missing or symlinked dependency report")
    if path.stat().st_size > MAX_BYTES:
        raise AuditError("dependency report exceeds size limit")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AuditError("unreadable dependency report") from exc


def resolved_graph(text: str, configuration: str) -> list[tuple[str, str, str]]:
    """Capture actually resolved Maven modules from a bounded Gradle report."""
    if not re.search(r"(?m)^" + re.escape(configuration) + r"\s+-", text):
        raise AuditError("missing resolved configuration: " + configuration)
    if not re.search(r"(?m)^BUILD SUCCESSFUL(?:\s|$)", text):
        raise AuditError("dependency resolution not confirmed successful")
    if re.search(r"(?m)^\s*> Task .* FAILED\b|^\s*FAILURE:", text):
        raise AuditError("Gradle reported a failed task")
    entries: dict[tuple[str, str], str] = {}
    in_config = False
    for line in text.splitlines():
        if line.startswith(configuration + " -"):
            in_config = True
            continue
        if not in_config:
            continue
        if line.startswith("BUILD SUCCESSFUL"):
            break
        # Reject an unresolved Gradle edge BEFORE parsing a valid-looking
        # coordinate; otherwise '+--- group:artifact:version FAILED' passes.
        if re.search(r"\bFAILED\b|Could not resolve", line):
            raise AuditError("unresolved dependency in " + configuration)
        match = NODE.match(line)
        if match is None:
            continue
        group, artifact, requested, selected = match.groups()
        version = selected or requested
        if (any(symbol in requested + version for symbol in ("+", "[", "]", ","))
                or "latest" in (requested + version).lower()
                or "snapshot" in (requested + version).lower()
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", version)):
            raise AuditError("mutable or malformed Maven version")
        key = (group, artifact)
        if key in entries and entries[key] != version:
            raise AuditError("conflicting resolved Maven versions")
        entries[key] = version
    return sorted((group, artifact, ver) for (group, artifact), ver in entries.items())


def audit(runtime_text: str, test_text: str) -> dict:
    runtime = resolved_graph(runtime_text, "debugRuntimeClasspath")
    tests = resolved_graph(test_text, "debugUnitTestRuntimeClasspath")
    runtime_set = {(g, a) for g, a, _ in runtime}
    test_set = {(g, a): v for g, a, v in tests}
    for key, expected in TEST_ALLOWED.items():
        if key in runtime_set:
            raise AuditError("test-only module leaked into Android app runtime")
        if test_set.get(key) != expected:
            raise AuditError("required test-only module absent or version changed")
    # Record *all* scoped module coordinates, including transitive dependencies.
    # Licenses of unreviewed modules must never be inferred from group names.
    def components(items: list[tuple[str, str, str]], scope: str) -> list[dict]:
        return [
            {
                "purl": f"pkg:maven/{g}/{a}@{v}",
                "scope": scope,
                "licenseEvidence": TEST_LICENSE_METADATA.get((g, a), "NOT_VERIFIED"),
                "licenseApproved": False,
            }
            for g, a, v in items
        ]

    return {
        "schemaVersion": 1,
        "scope": "android-:app:debugRuntimeClasspath+debugUnitTestRuntimeClasspath",
        "graphAudit": "PASS",
        "inventoryCompleteness": "PARTIAL",
        "pluginClasspathCovered": False,
        "releaseApproved": False,
        "licenseClosure": "NOT_VERIFIED",
        "apkPackagingVerified": False,
        "runtimeComponents": components(runtime, "android-debug-runtime"),
        "testComponents": components(tests, "android-debug-unit-test"),
        "componentCounts": {"runtime": len(runtime), "test": len(tests)},
        "manualGates": [
            "plugin_and_toolchain_dependency_graph",
            "resolved_artifact_hashes_and_licenses",
            "product_license_and_complete_NOTICE_SBOM",
            "signed_package_runtime_audit",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = audit(read_report(args.runtime), read_report(args.test))
    except AuditError as exc:
        print("BLOCKED: dependency graph audit: " + str(exc), file=sys.stderr)
        return 2
    payload = json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
