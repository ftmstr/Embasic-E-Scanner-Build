#!/usr/bin/env python3
"""Reconcile actual selected Gradle POM gaps with source-research metadata.

Research QUEUE only. No POM name, parent, upstream URL, cache hash or official
repository fetch authorizes a redistributable license or a product release.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

MAX_INPUT = 4_000_000
MAX_MODULES = 512
MAX_TARGETS = 32
PURL = re.compile(r"pkg:maven/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
HOSTS = ("https://repo.maven.apache.org/maven2",
         "https://dl.google.com/dl/android/maven2")
GAPS = {"POM_NOT_CACHED": "pomNotCached",
        "POM_WITHOUT_DIRECT_LICENSE_NAME": "pomWithoutDirectLicenseName",
        "UNREADABLE_POM": "unreadablePom"}


class AuditError(ValueError):
    pass


def _purl(value: object) -> tuple[str, str, str]:
    match = PURL.fullmatch(value) if isinstance(value, str) else None
    if match is None or any(x in ("", ".", "..") or ".." in x or
                            x.startswith(".") for x in (match.groups() if match else ())):
        raise AuditError("invalid or unsafe selected Maven coordinate")
    return match.groups()


def _flags(data: dict, negative: dict, context: str) -> None:
    if not isinstance(data, dict) or any(data.get(k) != v for k, v in negative.items()):
        raise AuditError("unsafe or elevated " + context + " legal/provenance assertions")


def _source_targets(modules: list[dict]) -> dict[str, set[str]]:
    targets: dict[str, set[str]] = {}
    for mod in modules:
        if mod["licenseMetadataState"] == "POM_NOT_CACHED":
            targets.setdefault(mod["purl"], set()).add("SELECTED_POM_NOT_CACHED")
        for chain in mod.get("parentPomEvidence", []):
            if not isinstance(chain, list) or len(chain) > 6:
                raise AuditError("unbounded parent POM evidence")
            for row in chain:
                if not isinstance(row, dict) or row.get("licenseApproved") is not False:
                    raise AuditError("elevated or malformed parent POM claim")
                if row.get("status") != "PARENT_POM_NOT_CACHED":
                    continue
                coord = row.get("coordinate")
                if not isinstance(coord, str) or len(coord.split(":")) != 3:
                    raise AuditError("unsafe ancestor identity")
                group, artifact, version = coord.split(":")
                target = f"pkg:maven/{group}/{artifact}@{version}"
                _purl(target)
                targets.setdefault(target, set()).add("MISSING_PARENT_POM")
    if not 0 < len(targets) <= MAX_TARGETS:
        raise AuditError("unbounded or empty source research target set")
    return targets


def audit(plugin: dict, research: dict) -> dict:
    _flags(plugin, {
        "status": "PASS_WITH_GAPS",
        "schemaVersion": 1,
        "scope": "Android Gradle root/app buildEnvironment LOCAL cache evidence only",
        "partialNoticeCheck": "PASS",
        "originVerified": False,
        "parentLicenseInheritanceVerified": False,
        "licenseApproval": "NOT_VERIFIED",
        "inventoryCompleteness": "PARTIAL",
        "noticeClosure": "NOT_VERIFIED",
        "sbomComplete": False,
        "releaseApproved": False,
    }, "selected plugin inventory")
    modules = plugin.get("modules")
    counts = plugin.get("counts")
    gaps = plugin.get("missingDirectLicenseEvidence")
    if (not isinstance(modules, list) or not 1 <= len(modules) <= MAX_MODULES
            or not isinstance(counts, dict) or not isinstance(gaps, list)
            or counts.get("modules") != len(modules)):
        raise AuditError("missing or inconsistent selected Gradle module counts")
    seen: set[str] = set()
    expected: dict[str, str] = {}
    derived = {key: 0 for key in GAPS.values()}
    direct = 0
    for mod in modules:
        if not isinstance(mod, dict):
            raise AuditError("invalid module row")
        purl = mod.get("purl")
        _purl(purl)
        if purl in seen:
            raise AuditError("duplicate selected Maven module")
        seen.add(purl)
        state = mod.get("licenseMetadataState")
        licenses = mod.get("pomDeclaredLicenses")
        if not isinstance(licenses, list):
            raise AuditError("missing supplier-declared license list")
        if state in GAPS:
            if licenses:
                raise AuditError("direct license metadata disguised as missing")
            expected[purl] = state
            derived[GAPS[state]] += 1
        elif state == "DIRECT_POM_LICENSE_NAME":
            if not licenses:
                raise AuditError("fabricated direct-license metadata")
            direct += 1
        else:
            raise AuditError("unknown direct POM metadata status")
        for lic in licenses:
            if (not isinstance(lic, dict)
                    or lic.get("evidence") != "UNVERIFIED_SUPPLIER_POM"
                    or not isinstance(lic.get("name"), str)
                    or not lic["name"].strip()
                    or lic.get("licenseApproved", False) is not False):
                raise AuditError("elevated supplier-declared license metadata")
        # Check ancestry even if a direct child declares a license.
        _source_targets_parent_check(mod)
    if (counts.get("pomWithLicenseNames") != direct
            or any(counts.get(k) != value for k, value in derived.items())
            or len(expected) != len(gaps)):
        raise AuditError("stale or contradictory direct POM gap counters")
    extracted = {}
    for row in gaps:
        if not isinstance(row, dict):
            raise AuditError("bad selected gap")
        purl = row.get("purl")
        _purl(purl)
        if purl in extracted or expected.get(purl) != row.get("reason"):
            raise AuditError("duplicate, missing or elevated selected POM gap")
        if row.get("unresolvedPomParents") != next(
                mod["unresolvedPomParents"] for mod in modules if mod["purl"] == purl):
            raise AuditError("selected POM parent hint drift")
        extracted[purl] = row
    if set(extracted) != set(expected):
        raise AuditError("selected POM gap list was silently narrowed")
    targets = _source_targets(modules)
    _flags(research, {
        "schemaVersion": 1,
        "status": "PARTIAL_EVIDENCE_ONLY",
        "scope": "PUBLIC-Gradle-selected-missing-POM-and-parent-only",
        "originVerified": False,
        "artifactBinaryVerified": False,
        "parentLicenseInheritanceVerified": False,
        "licenseClosure": "NOT_VERIFIED",
        "sbomComplete": False,
        "releaseApproved": False,
    }, "remote source POM research")
    rows = research.get("records")
    if (not isinstance(rows, list) or len(rows) != len(targets)
            or research.get("targets") != len(rows)
            or research.get("originalDirectLicenseGaps") != len(expected)):
        raise AuditError("mismatched research targets or original gaps")
    fetched = 0
    source = {}
    for row in rows:
        if not isinstance(row, dict):
            raise AuditError("bad remote POM research row")
        purl = row.get("purl")
        group, artifact, version = _purl(purl)
        if purl not in targets or purl in source or row.get("reasons") != sorted(targets[purl]):
            raise AuditError("missing, duplicate or unselected upstream POM")
        _flags(row, {"licenseApproved": False, "publisherSignatureVerified": False},
               "remote POM")
        status = row.get("status")
        licenses = row.get("supplierDeclaredLicenses")
        if not isinstance(licenses, list):
            raise AuditError("missing remote supplier POM metadata")
        if status == "UPSTREAM_POM_METADATA_RETRIEVED":
            fetched += 1
            expected_suffix = ("/" + group.replace(".", "/") + "/" + artifact
                               + "/" + version + "/" + artifact + "-" + version + ".pom")
            url = row.get("officialRepositoryUrl")
            if (not isinstance(url, str) or
                    not any(url == host + expected_suffix for host in HOSTS)
                    or not isinstance(row.get("sha256"), str)
                    or not SHA.fullmatch(row["sha256"])
                    or not isinstance(row.get("byteSize"), int)
                    or not 0 < row["byteSize"] <= 1_048_576):
                raise AuditError("mismatched upstream POM URL, identity or hash evidence")
        elif status == "UPSTREAM_POM_UNAVAILABLE":
            if (row.get("officialRepositoryUrl") is not None
                    or row.get("sha256") is not None
                    or row.get("byteSize") is not None
                    or licenses or row.get("unverifiedParent") is not None):
                raise AuditError("missing remote POM smuggles source declarations")
        else:
            raise AuditError("unexpected remote POM verification state")
        for lic in licenses:
            if (not isinstance(lic, dict)
                    or lic.get("evidence") != "UNVERIFIED_REMOTE_POM_DECLARATION"
                    or not isinstance(lic.get("name"), str) or not lic["name"].strip()
                    or lic.get("licenseApproved", False) is not False):
                raise AuditError("supplier metadata escalated to license grant")
        parent = row.get("unverifiedParent")
        if parent is not None:
            if not isinstance(parent, str) or len(parent.split(":")) != 3:
                raise AuditError("unsafe remote POM parent")
            _purl("pkg:maven/" + parent.replace(":", "/", 1).replace(":", "@", 1))
        source[purl] = row
    if (set(source) != set(targets)
            or research.get("remotePomMetadataRetrieved") != fetched
            or research.get("stillUnretrieved") != len(rows) - fetched):
        raise AuditError("remote POM target/retrieval counts inconsistent")
    actions = []
    for mod in sorted(modules, key=lambda x: x["purl"]):
        purl = mod["purl"]
        if purl not in expected:
            continue
        own_source = source.get(purl)
        parents = sorted({
            "pkg:maven/" + a["coordinate"].replace(":", "/", 1).replace(":", "@", 1)
            for chain in mod.get("parentPomEvidence", [])
            for a in chain if a["status"] == "PARENT_POM_NOT_CACHED"
        })
        parents_found = [p for p in parents if source.get(p, {}).get("status")
                         == "UPSTREAM_POM_METADATA_RETRIEVED"]
        if expected[purl] == "POM_NOT_CACHED":
            next_action = ("REVIEW_REMOTE_CHILD_LICENSE_TEXT_AND_BINARY_BOUNDARY"
                           if own_source and own_source["status"] == "UPSTREAM_POM_METADATA_RETRIEVED"
                           else "OBTAIN_EXACT_CHILD_POM_AND_LICENSE_TEXT")
        else:
            next_action = "REVIEW_CHILD_DIRECT_LICENSE_AND_APPLICABLE_PARENT_TERMS"
        actions.append({
            "purl": purl,
            "directPomState": expected[purl],
            "scope": sorted(mod.get("scopes", [])),
            "selectedParentHints": sorted(mod.get("unresolvedPomParents", [])),
            "remoteChildMetadataStatus": (own_source["status"] if own_source
                                         else "NOT_IN_BOUNDED_SOURCE_TARGETS"),
            "remoteChildDeclaredLicenseNames": (
                [x["name"] for x in own_source["supplierDeclaredLicenses"]]
                if own_source else []),
            "retrievedMissingParents": parents_found,
            "missingParentTargets": parents,
            "nextAction": next_action,
            "evidenceOnly": True,
            "licenseApproved": False,
            "parentLicenseInheritanceVerified": False,
            "redistributionRightsVerified": False,
        })
    return {
        "schemaVersion": 1,
        "status": "REVIEW_QUEUE_ONLY_LEGAL_NO_GO",
        "scope": "PUBLIC Android Gradle buildEnvironment selected POM gaps, not release runtime",
        "counts": {"selectedModules": len(modules), "directPOMLicenseGaps": len(actions),
                   "childPOMNotCached": derived["pomNotCached"],
                   "childPOMWithoutDirectLicenseName": derived["pomWithoutDirectLicenseName"],
                   "unreadableChildPOM": derived["unreadablePom"],
                   "remoteResearchTargets": len(rows),
                   "remoteMetadataRetrieved": fetched,
                   "remoteMetadataUnavailable": len(rows) - fetched},
        "reviewQueue": actions,
        "sourceResearchNotLicenceGrant": True,
        "allChildGapsRemainUnresolved": True,
        "microsoftSDKBuildToolsExactRedistRights": "NOT_VERIFIED_SEPARATE_GATE",
        "licenseClosure": "NOT_VERIFIED",
        "parentLicenseInheritanceVerified": False,
        "publisherSignatureVerified": False,
        "noticeClosure": "NOT_VERIFIED",
        "sbomComplete": False,
        "releaseApproved": False,
    }


def _source_targets_parent_check(mod: dict) -> None:
    for chain in mod.get("parentPomEvidence", []):
        if not isinstance(chain, list) or len(chain) > 6:
            raise AuditError("unsafe parent evidence chain")
        for row in chain:
            if (not isinstance(row, dict) or
                    row.get("licenseApproved") is not False
                    or row.get("status") not in (
                        "PARENT_POM_NOT_CACHED", "PARENT_POM_METADATA_ONLY",
                        "UNREADABLE_PARENT_POM", "DEPTH_LIMIT_NOT_VERIFIED")):
                raise AuditError("parent POM evidence legal scope escalated")


def _read(path: Path) -> dict:
    if (path.is_symlink() or not path.is_file()
            or not 0 < path.stat().st_size <= MAX_INPUT):
        raise AuditError("missing, symlinked or oversized input report")
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plugin-report", type=Path, required=True)
    p.add_argument("--pom-research", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        data = audit(_read(args.plugin_report), _read(args.pom_research))
        args.output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (AuditError, OSError, TypeError, ValueError, KeyError) as exc:
        print("BLOCKED: selected POM licensing research reconciliation: " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps({
        "status": data["status"], "counts": data["counts"],
        "allChildGapsRemainUnresolved": True,
        "microsoftSDKBuildToolsExactRedistRights": "NOT_VERIFIED_SEPARATE_GATE",
        "releaseApproved": False
    }, sort_keys=True))
    for item in data["reviewQueue"]:
        print("LEGAL_REVIEW_GAP:", item["purl"], item["directPomState"],
              item["remoteChildMetadataStatus"], item["nextAction"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
