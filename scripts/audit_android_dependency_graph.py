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


# Only metadata labels; these strings are not proof of license grants.
NOTICE_LABELS = {
    # 18-Nov exact resolved debugRuntimeClasspath (GitHub Actions 44384810611).
    # Supplier POM label is not a hash of exact POM/JAR or license approval.
    "pkg:maven/com.android.databinding/baseLibrary@8.13.2": "Apache-2.0",
    # 19-Nov real CI run 44576080885/JSpecify official POM/JAR and
    # immutable v1.0.0 tagged LICENSE bytes; NOT a distribution grant.
    "pkg:maven/org.jspecify/jspecify@1.0.0": "Apache-2.0",
    # 19-Nov official Maven Central/JAR-cache byte parity and immutable Kotlin
    # 1.8.1-tagged LICENSE proved at PUBLIC Actions 44605162262; NOT legal GO.
    "pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm@1.8.1": "Apache-2.0",
    # Real 19-Nov official Maven JAR/POM and immutable Kotlin 1.8.1 tagged
    # LICENSE byte parity at CI 44611323479; no distribution authorization.
    "pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-android@1.8.1": "Apache-2.0",
    # Actual 20-Nov immutable Kotlinx Serialization v1.7.3 source LICENSE
    # and separate NOTICE, official Maven POM/JAR local Gradle byte parity
    # (CI 44626811889); source label only, redistribution still NOT VERIFIED.
    "pkg:maven/org.jetbrains.kotlinx/kotlinx-serialization-core-jvm@1.7.3": "Apache-2.0",
    "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.3.21": "Apache-2.0",
    "pkg:maven/org.jetbrains/annotations@13.0": "Apache-2.0",
    "pkg:maven/junit/junit@4.13.2": "EPL-1.0",
    "pkg:maven/org.hamcrest/hamcrest-core@1.3": "New BSD",
}


def check_partial_notice(inventory: dict, notice: str) -> None:
    """Check each resolved coordinate has exactly one correctly labelled row.

    This is a *partial consistency check*, not a full license review or SBOM.
    Unknown future dependencies must fail until explicitly reviewed/recorded.
    """
    if "REVIEW INCOMPLETE" not in notice or "NOT a full SBOM" not in notice:
        raise AuditError("NOTICE must explicitly state its incomplete scope")
    purls = {item["purl"] for item in
             inventory["runtimeComponents"] + inventory["testComponents"]}
    missing_or_duplicate = []
    for purl in sorted(purls):
        rows = [line for line in notice.splitlines()
                if line.startswith("|") and f"\x60{purl}\x60" in line]
        if len(rows) != 1:
            missing_or_duplicate.append((purl, len(rows)))
            continue
        # Parse the exact three-column Markdown row, not a coincidental
        # substring elsewhere in a row (including the scope column).
        fields = [value.strip() for value in rows[0].split("|")]
        if (len(fields) != 5 or fields[0] or fields[-1]
                or fields[1] != f"`{purl}`"):
            raise AuditError("malformed or imprecise Maven NOTICE table row")
        expected = NOTICE_LABELS.get(purl)
        label = fields[3]
        if expected is None or expected not in label:
            raise AuditError("unreviewed Maven module or mismatched license label")
        if ("NOT VERIFIED" not in label and "review OPEN" not in label
                or "APPROVED" in label):
            raise AuditError("NOTICE row makes unreviewed distribution claim")
        if purl in (
            "pkg:maven/junit/junit@4.13.2",
            "pkg:maven/org.hamcrest/hamcrest-core@1.3",
        ) and "tests ONLY" not in rows[0]:
            raise AuditError("test-only module lacks runtime exclusion notice")
    if missing_or_duplicate:
        # Enumerate all Gradle-resolved missing/duplicate purls in one report.
        # Do not manufacture license labels, suppress the gate, or turn gaps
        # into a 'PASS' when the network-resolved graph changes.
        examples = "; ".join(
            f"{purl} (found {count})"
            for purl, count in missing_or_duplicate[:128])
        if len(missing_or_duplicate) > 128:
            examples += f"; ... plus {len(missing_or_duplicate) - 128} further gaps"
        raise AuditError(
            f"missing or duplicate resolved Maven NOTICE rows: "
            f"total={len(missing_or_duplicate)}; {examples}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--notice", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = audit(read_report(args.runtime), read_report(args.test))
        check_partial_notice(result, read_report(args.notice))
        result["noticeScopeCheck"] = "PASS"
        result["noticeCompleteness"] = "PARTIAL"
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
