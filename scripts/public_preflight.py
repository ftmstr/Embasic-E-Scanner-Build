#!/usr/bin/env python3
"""Read-only PUBLIC E-Scanner preflight; never certifies product release.

Requires only Python standard library. It does not fetch, import, or execute code,
inspect private repositories, or print any file contents, checksums, credentials,
or proprietary sample bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

CHECKSUM = re.compile(r"[0-9a-fA-F]{64}\Z")
# Published upstream values: https://gradle.org/release-checksums/ (8.14.6).
OFFICIAL_GRADLE_URL = "https://services.gradle.org/distributions/gradle-8.14.6-bin.zip"
OFFICIAL_DIST_SHA256 = "7988ed071b2a07900e2ec715fca15c6ab72bce6db433af301fa7fa7e9407bd24"
OFFICIAL_WRAPPER_SHA256 = "ad16bca46cb71bb5887c546860d93992aeee35c1fdaf4a242b0a612375d937e0"


def safe_file(root: Path, rel: str, max_bytes: int | None = None) -> bool:
    """Reject symbolic links along a path and avoid reading unbounded inputs."""
    cur = root
    if root.is_symlink():
        return False
    for component in Path(rel).parts:
        if component in (".", ".."):
            return False
        cur = cur / component
        if cur.is_symlink():
            return False
    if not cur.is_file():
        return False
    if max_bytes is not None and cur.stat().st_size > max_bytes:
        return False
    return True


def gate(name: str, ok: bool, note: str) -> dict[str, str]:
    return {"name": name, "status": "PASS" if ok else "BLOCKED", "note": note}


def audit(root: Path) -> dict[str, object]:
    root = Path(root)
    results = []
    license_paths = ("LICENSE", "LICENSE.txt", "LICENSE.md")
    notice_paths = ("THIRD-PARTY-NOTICES.md", "NOTICE", "NOTICE.md")
    has_license = any(safe_file(root, p, 1024 * 1024) for p in license_paths)
    has_notice = any(safe_file(root, p, 1024 * 1024) for p in notice_paths)
    results.append(gate("license_presence", has_license, "Presence only; authorship/terms review remains manual"))
    results.append(gate("notice_presence", has_notice, "Presence only; dependency inventory and SBOM remain manual"))

    gradle_paths = ("android/settings.gradle.kts", "android/build.gradle.kts",
                    "android/app/build.gradle.kts", "android/gradlew")
    has_gradle = all(safe_file(root, p, 1024 * 1024) for p in gradle_paths)
    results.append(gate("android_build_sources", has_gradle,
                        "Clean-room Gradle project and wrapper script must exist"))

    props_name = "android/gradle/wrapper/gradle-wrapper.properties"
    has_props = safe_file(root, props_name, 16 * 1024)
    url_ok = False
    dist_hash_ok = False
    if has_props:
        try:
            props = (root / props_name).read_text(encoding="utf-8")
            values = {}
            for line in props.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() in values:
                    values[k.strip()] = ""  # ambiguous key must fail closed
                else:
                    values[k.strip()] = v.strip().replace("\\:", ":")
            url = values.get("distributionUrl", "")
            url_ok = url == OFFICIAL_GRADLE_URL
            dist_hash_ok = values.get("distributionSha256Sum", "").lower() == OFFICIAL_DIST_SHA256
        except (UnicodeError, OSError, ValueError):
            pass
    results.append(gate("gradle_distribution_pin", has_props and url_ok and dist_hash_ok,
                        "Pinned official Gradle 8.14.6 distribution digest (no downloaded-binary attestation)"))

    jar = "android/gradle/wrapper/gradle-wrapper.jar"
    checksum_file = jar + ".sha256"
    has_jar = safe_file(root, jar, 2 * 1024 * 1024)
    has_checksum = safe_file(root, checksum_file, 256)
    jar_ok = False
    if has_jar and has_checksum:
        try:
            declared = (root / checksum_file).read_text(encoding="ascii").strip()
            if CHECKSUM.fullmatch(declared) and declared.lower() == OFFICIAL_WRAPPER_SHA256:
                digest = hashlib.sha256()
                with (root / jar).open("rb") as handle:
                    for chunk in iter(lambda: handle.read(65536), b""):
                        digest.update(chunk)
                jar_ok = digest.hexdigest() == declared.lower()
        except (OSError, UnicodeError, ValueError):
            pass
    results.append(gate("wrapper_jar_integrity", jar_ok,
                        "Official upstream JAR checksum and content digest must match; provenance/license review stays manual"))
    machine_ready = all(x["status"] == "PASS" for x in results)
    return {"schemaVersion": 1, "scope": "public-source-structural-preflight",
            "machinePreflight": "PASS" if machine_ready else "BLOCKED",
            "releaseStatus": "NOT_VERIFIED", "releaseApproved": False,
            "manualGates": ["license_rights_and_transitives", "clean_source_provenance",
                            "wrapper_binary_origin", "SBOM_and_NOTICE_completeness",
                            "Android_and_Windows_device_smoke", "security_and_signed_packages"],
            "gates": results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--strict", action="store_true", help="Exit 2 on blocked structural preflight")
    args = parser.parse_args(argv)
    result = audit(args.root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if args.strict and result["machinePreflight"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
