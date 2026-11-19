# PUBLIC Gradle 8.13 classifier byte-parity gate — 9 November 2026

**PUBLIC only:** ftmstr/Embasic-E-Scanner-Build, branch
fix/pdf-fixture-selftest-20261018, PR #1 remains OPEN/DRAFT.
**This is build-tool integrity evidence, not a release or legal clearance.**

## What this change checks

The 8 Nov 2026 Android CI recorded 147 selected Gradle plugin modules,
295 locally fingerprinted cached files, and three Kotlin 2.3.21
gradle813-classified JARs. One (kotlin-gradle-plugin) had independent upstream
byte parity already. The other two were LOCAL_ONLY; the new gate covers only:

| Maven purl | Exact classified JAR | Prior local SHA-256 |
| --- | --- | --- |
| pkg:maven/org.jetbrains.kotlin/fus-statistics-gradle-plugin@2.3.21 | fus-statistics-gradle-plugin-2.3.21-gradle813.jar | 73379b384d9da66419b5f4d5c83de1a99dd7f195662bc45c39443859e63e18b2 |
| pkg:maven/org.jetbrains.kotlin/kotlin-gradle-plugin-api@2.3.21 | kotlin-gradle-plugin-api-2.3.21-gradle813.jar | ad58d2638ee041f6ce4e73e9782ebf528e18cf9003b1099aa7045ec958e3c195 |

The static official source prefix is
https://repo.maven.apache.org/maven2 ; exact URLs must match
the hardcoded PURL/version/classifier identities. No alternate host,
untrusted URL, user token, redirect, local/classifier guess or 404 fallback
can produce PASS. Remote bytes must have both the previously observed pinned
SHA-256 and the selected Gradle local-cache SHA-256, *and* exactly match
local byteSize. A mismatch fails closed.

Synthetic unit tests test changes to the bytes, SHA/size, classifier metadata,
scope flags, duplicate module/file records, missing local/remote bytes,
transport outage, redirect, arbitrary host, forged licence/release approval,
and boundedness. Actual Maven Central verification is executed in
Android Kotlin Foundation CI and saved as a partial dependency-evidence JSON.

A successful exact-byte comparison establishes byte equality to the HTTPS
Maven Central endpoint at audit time. It DOES NOT independently establish
publisher signatures, signing key custody, repository authenticity beyond
the TLS endpoint, binary-to-source reproducibility, commercial licence grants,
transitive NOTICE closure, or a production SBOM.

## Independent legal and licensing decision queue

**42 direct child POM licence metadata gaps remain OPEN** among 147
selected build-tool modules: 12 POM_NOT_CACHED and 30
POM_WITHOUT_DIRECT_LICENSE_NAME. The observed 59 parent POM chain
links are provenance *hints*, not inherited legal grants; 4 prior parent
references were not locally available. Each exact component must undergo
its own authoritative license-text and transitive obligation review;
metadata labels alone cannot be promoted to approvals. The closed-world
two-classifier check cannot reduce the 42 gap counter.

**NOTICE / LICENSES / SBOM:** THIRD-PARTY-NOTICES.md is a partial
build/runtime/test inventory, not an installable release's complete
third-party notices. Product root LICENSE must not be created without
the copyright holder's written choice/approval. Before release, obtain
license texts, attribution/NOTICE requirements, runtime-versus-build
separation, reproducible scoped dependency graph, SPDX/CycloneDX with
file/package checksums, and signed APK/AAB/Windows package contents.
Treat EPL/LGPL/MPL/GPL/AGPL boundaries separately rather than inferring
redistribution permission from a POM or a local SHA.

**Microsoft.Windows.SDK.BuildTools 10.0.26100.4654** remains a temporary
Windows AppSDK 2.6.4 NuGet restore observation: 16 resolved packages,
15 with direct supplier nuspec licence declarations, the BuildTools nuspec
with legacy licenseUrl but NO direct <license>. Official NuGet package page
describes BUILD TOOLS and no supported framework assets; that is NOT permission
to copy tools or SDK files into a commercial installer. The applicable
version-specific licence/REDIST.TXT file list, packaging boundary,
redistributable classification and copyright/notice obligations require a
separate legal+technical review. Microsoft general SDK/EWDK and Windows AppSDK
deployment documents are contextual guidance, NOT an exact-package grant.

Sources to review:
- https://www.nuget.org/packages/Microsoft.Windows.SDK.BuildTools/10.0.26100.4654
- https://learn.microsoft.com/en-us/legal/windows-sdk/license-terms-ewdk
- https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/deploy-packaged-apps
- https://github.com/microsoft/win32metadata/blob/main/licenses/sdk_license.txt
  (older example licence; do NOT substitute for version 10.0.26100.4654)

## Product gates remain separate

Android independently usable scan/crop/transform/OCR/searchable PDF/export,
Windows native GUI scan and workspace, QR/TLS HTTPS+WSS certificate pinning,
one-time token/replay protection, full-resolution SHA transfers, golden
cross-device parity, staging/reopen/geometry/atomic export, scale/device
smokes, signed binaries, ad privacy, SBOM, NOTICE and rollback are all
NOT VERIFIED for release. Do not convert CI foundation checks into
native or release acceptance. No PRIVATE, main, merge or force operation.
