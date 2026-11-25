#!/usr/bin/env python3
"""Exact tracing 1.2.0 published artifacts; never legal/release approval."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
from urllib import request
import xml.etree.ElementTree as ET
import zipfile
from audit_androidx_futures110_source_review import AuditError, RefuseRedirect, children, one

GAV = "androidx.tracing:tracing:1.2.0"
PURL = "pkg:maven/androidx.tracing/tracing@1.2.0"
BASE = "https://dl.google.com/dl/android/maven2/androidx/tracing/tracing/1.2.0/tracing-1.2.0"
URLS = {"pom": BASE + ".pom", "aar": BASE + ".aar", "sources": BASE + "-sources.jar",
        "license": "https://raw.githubusercontent.com/androidx/androidx/4a63db244f62d809948bc2fb6676d62710c72609/LICENSE.txt"}
LIMITS = {"pom": 65536, "aar": 2000000, "sources": 2000000, "license": 20000}
ROOT_LICENSE_SHA = "809fa1ed21450f59827d1e9aec720bbc4b687434fa22283c6cb5dd82a47ab9c0"
# Initial real hosted CI receipt required before POM/AAR/sources pins.
CLASS = "androidx/tracing/Trace.class"
SOURCE = "androidx/tracing/Trace.java"

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def fetch(kind):
    req = request.Request(URLS[kind], headers={"User-Agent": "Embasic-Tracing120-Audit/1"})
    with request.build_opener(RefuseRedirect).open(req, timeout=25) as resp:
        if resp.status != 200:
            raise AuditError("non-200 response")
        return resp.read(LIMITS[kind] + 1)

def checked(kind, raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= LIMITS[kind]:
        raise AuditError("invalid size: " + kind)
    return raw

def pom_info(raw):
    checked("pom", raw)
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise AuditError("unsafe POM")
    root = ET.fromstring(raw)
    if root.tag.rsplit("}", 1)[-1] != "project":
        raise AuditError("invalid project")
    if ":".join(one(root, x) for x in ("groupId", "artifactId", "version")) != GAV:
        raise AuditError("wrong POM GAV")
    licenses = children(root, "licenses")
    if len(licenses) > 1:
        raise AuditError("ambiguous license metadata")
    claims = [one(x, "name") for x in children(licenses[0], "license")] if licenses else []
    if not claims or any("apache" not in c.lower() or "2.0" not in c for c in claims):
        raise AuditError("unexpected or missing direct license claim")
    return claims

def archive_info(kind, raw):
    checked("aar" if kind in ("aar", "jar") else kind, raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        entries = z.infolist()
        names = [x.filename for x in entries]
        if not 1 <= len(entries) <= 2000 or sum(x.file_size for x in entries) > 16000000:
            raise AuditError("archive budget")
        if len(set(names)) != len(names):
            raise AuditError("duplicate archive path")
        for x in entries:
            if (x.filename.startswith("/") or "\\" in x.filename
                    or ".." in x.filename.split("/") or ":" in x.filename
                    or stat.S_ISLNK(x.external_attr >> 16) or x.flag_bits & 1):
                raise AuditError("unsafe archive member")
        if z.testzip() is not None:
            raise AuditError("bad CRC")
        required = "classes.jar" if kind == "aar" else CLASS if kind == "jar" else SOURCE
        if required not in names:
            raise AuditError("expected archive/class/source missing")
        marker = z.read(required)
        if kind == "aar" and "AndroidManifest.xml" not in names:
            raise AuditError("AAR manifest missing")
        if kind == "aar" and not z.read("AndroidManifest.xml").strip():
            raise AuditError("empty AAR manifest")
        if kind == "jar" and not marker.startswith(b"\xca\xfe\xba\xbe"):
            raise AuditError("bad class header")
        if kind == "sources" and b"Licensed under the Apache License, Version 2.0" not in marker:
            raise AuditError("expected published source license header missing")
        legal = []
        for x in entries:
            name = x.filename.rsplit("/", 1)[-1].lower()
            if not x.is_dir() and re.match(r"^(license|notice|copying|copyright)([._-].*)?$", name):
                data = z.read(x)
                legal.append({"path": x.filename, "sha256": sha(data), "bytes": len(data)})
        result = {"entries": len(entries), "legalEntries": legal,
                  "marker": required, "markerSha256": sha(marker)}
        if kind == "aar":
            result["classesJar"] = archive_info("jar", marker)
        return result

def audit(cache, runtime, test, getter=fetch, license_pin=ROOT_LICENSE_SHA):
    graphs = {}
    pattern = re.compile(r"(?<![\w.-])" + re.escape(GAV) + r"(?![\w.-])")
    for label, path in (("debugRuntimeClasspath", runtime), ("debugUnitTestRuntimeClasspath", test)):
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 2000000:
            raise AuditError("unsafe graph")
        content = path.read_text(encoding="utf-8")
        if "BUILD SUCCESSFUL" not in content:
            raise AuditError("unsuccessful graph")
        graphs[label] = any(pattern.search(line) and not re.search(re.escape(GAV) + r"\s+->", line)
                            for line in content.splitlines())
    if not any(graphs.values()):
        raise AuditError("exact selected coordinate missing")
    folder = cache
    for part in ("androidx.tracing", "tracing", "1.2.0"):
        if folder.is_symlink():
            raise AuditError("symlink cache")
        folder = folder / part
    if folder.is_symlink():
        raise AuditError("symlink cache")
    candidates = list(folder.glob("*/tracing-1.2.0.aar"))
    if len(candidates) != 1 or candidates[0].is_symlink() or candidates[0].parent.is_symlink():
        raise AuditError("missing/ambiguous cache AAR")
    if not candidates[0].is_file() or not 0 < candidates[0].stat().st_size <= LIMITS["aar"]:
        raise AuditError("unsafe cached AAR")
    data = {k: checked(k, getter(k)) for k in URLS}
    claims = pom_info(data["pom"])
    binary = archive_info("aar", data["aar"])
    source = archive_info("sources", data["sources"])
    if candidates[0].read_bytes() != data["aar"]:
        raise AuditError("Gradle AAR bytes differ")
    if sha(data["license"]) != license_pin:
        raise AuditError("later root license hash differs")
    return {"schemaVersion": 1, "purl": PURL, "status": "PUBLISHED_BYTES_MATCH_LEGAL_OPEN",
            "graphs": graphs, "directPomLicenseClaims": claims,
            "official": {k: {"url": URLS[k], "sha256": sha(v), "bytes": len(v)}
                         for k, v in data.items()},
            "binary": binary, "publishedSources": source, "gradleByteParity": True,
            "rootLicenseScope": "LATER_SNAPSHOT_ONLY", "releaseNoticeClosure": "NOT_VERIFIED",
            "licenseClosure": "NOT_VERIFIED", "sourceToBinaryReproducibility": "NOT_VERIFIED",
            "publisherSignatureVerified": False,
            "hashPinsVerified": False,
            "android85MissingNoticeRowsOpen": True, "gradle42PomGapsOpen": True,
            "sbomComplete": False, "releaseApproved": False}

def main():
    p = argparse.ArgumentParser()
    for name in ("cache", "runtime", "test", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    try:
        receipt = audit(a.cache, a.runtime, a.test)
    except (AuditError, OSError, ValueError, ET.ParseError, zipfile.BadZipFile, RuntimeError) as exc:
        print("BLOCKED TRACING120:", exc)
        return 2
    a.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("TRACING120_RECEIPT", json.dumps(receipt, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
