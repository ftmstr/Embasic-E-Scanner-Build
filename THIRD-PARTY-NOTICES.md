# Third-party notices — REVIEW INCOMPLETE

This file records **known PUBLIC-sourced build tools and two resolved Android Gradle configurations only**. It is
NOT a complete runtime dependency inventory, license audit, product-source
license, SBOM, release approval, or a substitute for reviewing transitive
dependencies. Distribution and signing remain **NO-GO** until all gates pass.

## Gradle Wrapper (version 8.14.6)

- Copyright: Gradle Inc. and the original Gradle authors.
- License of the copied Gradle build-tool source files: Apache License 2.0,
  subject to the exact upstream source license and additional upstream notices.
- Complete upstream source license file retained verbatim in
  `third_party/gradle-wrapper/LICENSE`.
- Upstream repository: https://github.com/gradle/gradle
- Immutable source commit: `c27417f274bd1cf2f36e1f93d54e3de840d54e43`
- Copied official files (without modifications):
  `android/gradlew`, `android/gradlew.bat`,
  `android/gradle/wrapper/gradle-wrapper.jar`.
- Wrapper JAR SHA-256 independently checked:
  `ad16bca46cb71bb5887c546860d93992aeee35c1fdaf4a242b0a612375d937e0`
- Distribution ZIP SHA-256 in `gradle-wrapper.properties`:
  `7988ed071b2a07900e2ec715fca15c6ab72bce6db433af301fa7fa7e9407bd24`.
- Official checksum list: https://gradle.org/release-checksums/
- Gradle Wrapper official validation: https://docs.gradle.org/current/userguide/gradle_wrapper.html

The JAR is a **build-tool wrapper**. It is not a linked runtime dependency
of the E-Scanner application or permission to relicense the user's software.
No production documents, secret credentials or PRIVATE repository files were
copied.


## JUnit 4.13.2 (test-only, NOT included in production APK)

- Direct dependency: `junit:junit:4.13.2`, declared exclusively with
  Gradle `testImplementation`.
- Declared license: Eclipse Public License 1.0 (EPL-1.0), not treated
  as permissive Apache/MIT/BSD. *Boundary review:* JVM unit-test runner only;
  it is not a linked/embedded runtime dependency and must not be bundled
  in the release APK/AAB. License obligation review for any redistribution
  of its artifact remains OPEN.
- Direct declared compile transitive: `org.hamcrest:hamcrest-core:1.3`,
  New BSD License (BSD-style), also scoped to the test runtime.
- Maven POMs / license metadata:
  https://central.sonatype.com/artifact/junit/junit/4.13.2
  https://central.sonatype.com/artifact/org.hamcrest/hamcrest-core/1.3
- Actual resolved dependency graph, runtime exclusion and byte-level
  inventory must be verified from GitHub Actions before any distribution.
  Test success by itself does not close the product license gate.

## Android resolved debug runtime and JVM test-only modules (30 October 2026)

The following exact Maven package coordinates were observed in PUBLIC Android
Gradle dependency reports at commit
`1c3a71de0e78f2aedbb598701a079a27fe8c8b00`, GitHub Actions run
`41056487701`, job `124065200691` (14 synthetic graph-audit tests PASS,
6 Android JUnit tests PASS). This is **NOT a full SBOM**, and Maven POM
license metadata is not proof of artifact bytes, legal clearance or product
release. Gradle plugins/build tooling, Android SDK and release variants are
outside this scoped inventory.

| Exact resolved Maven purl | Scope | Supplier POM license metadata |
| --- | --- | --- |
| `pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.3.21` | Android debug runtime; also JVM tests | Apache-2.0 (NOT VERIFIED for distribution) |
| `pkg:maven/org.jetbrains/annotations@13.0` | Android debug runtime; also JVM tests | Apache-2.0 (NOT VERIFIED for distribution) |
| `pkg:maven/junit/junit@4.13.2` | JVM local tests ONLY; absent from Android debug runtime | EPL-1.0 (test-only boundary, redistribution review OPEN) |
| `pkg:maven/org.hamcrest/hamcrest-core@1.3` | JVM local tests ONLY; absent from Android debug runtime | New BSD (test-only boundary, redistribution review OPEN) |

Publisher metadata (not independently verified byte-for-byte license texts):
- https://central.sonatype.com/artifact/org.jetbrains.kotlin/kotlin-stdlib/2.3.21
- https://central.sonatype.com/artifact/org.jetbrains/annotations/13.0
- https://central.sonatype.com/artifact/junit/junit/4.13.2
- https://central.sonatype.com/artifact/org.hamcrest/hamcrest-core/1.3

**Boundary:** The two Kotlin/JetBrains dependencies must undergo real
APK/AAB package inspection, notice/license retention and any transitive
artifact review. JUnit/Hamcrest are test-only and must remain excluded from
APK runtime graphs; their appearance here is NOT an EPL runtime waiver.
Every new resolved runtime/test Maven component requires a source-backed
NOTICE entry before the graph audit can pass. Even if all listed entries
exist, full product license/SBOM release closure stays **NOT VERIFIED**.

## Gradle build-tool root plugin transitive inventory — 2 November 2026

**NOT a complete SBOM. Review is incomplete.** These are local CI
build-tool cache observations, NOT the E-Scanner app release dependency
graph or a product-license approval. No downstream APK/AAB contains
these entire compiler/build-time dependencies merely because they appear
in the root Gradle plugin classpath.

The publicly linked Android buildEnvironment audit and local-cache verifier
recorded the following exact snapshot, with hashed binary/metadata evidence
retained as a GitHub Actions artifact:

- pluginModules: 147
- pluginLicenseNameMetadata: 105
- pluginMissingLicenseMetadata: 42
- pluginCachedFileHashes: 295

In the 2 November historical snapshot, all 147 selected Maven modules had
at least one local cached file hashed and 292 cached files were fingerprinted.
The later 8 November classifier-aware CI snapshot hashes 295 cached files
for those 147 modules; see the separate dated section below. Supplier POM license-name
metadata was available for only 105 modules. The other 42 modules have
no extracted POM license name; they MUST NOT be marked approved.
Even the 105 source labels are **UNVERIFIED_SUPPLIER_POM**, not legal or
binary-provenance approval. `originVerified=false`,
`sbomComplete=false`, `releaseApproved=false`.

Evidence: PUBLIC GitHub Actions run 41383659693, job 125079669267,
artifact `android-foundation-dependency-evidence` (14-day retention).
https://github.com/ftmstr/Embasic-E-Scanner-Build/actions/runs/41383659693

**Unresolved release gates:** actual Maven repository provenance/signatures,
binary publisher authenticity, transitive legal rights, license text retention,
all per-module notices, complete SPDX/CycloneDX/SBOM, Windows App SDK and
signed distributables. This section is a CI-scoped **PARTIAL** inventory,
not a complete third-party notices release obligation inventory.

## Classified Gradle JAR local SHA evidence — 8 November 2026

The PUBLIC Gradle build-tool cache inventory previously omitted selected
`artifact-version-classifier.jar` byte files, including Kotlin's reviewed
`gradle813` classifier. The new, bounded filename parser records classified
JAR byte sizes and local SHA-256 evidence under `sourceVerification =
LOCAL_BYTES_ONLY`, `binaryOrigin = NOT_VERIFIED`.

The actual Android CI on 8 November 2026 rejected the old snapshot
`pluginCachedFileHashes: 292` with explicit expected marker
`pluginCachedFileHashes: 295`. This partial NOTICE counter has been
updated to 295 **only because of that independently observed CI result**.
The classified files are not approved as signed publisher-origin artifacts,
and source/testing classifiers must not be treated as linked product runtime.

All 42 unresolved direct child POM license metadata gaps (12 POMs not
cached, 30 POMs without direct license names) remain independent of these
byte hash counts. Do not infer legal
license permissions or a complete build-tool/software bill of materials from
a larger number of locally fingerprinted cache files.

## Exact Maven Central Kotlin classifier source-byte comparison — 9 November 2026

The PUBLIC source integrity gate in scripts/audit_gradle813_classifier_jars.py
and its offline negative tests covers **only two build-tool classifier JARs**
not independently compared in the 8 November report. Fixed PURL/filename/SHA:

- pkg:maven/org.jetbrains.kotlin/fus-statistics-gradle-plugin@2.3.21,
  fus-statistics-gradle-plugin-2.3.21-gradle813.jar,
  73379b384d9da66419b5f4d5c83de1a99dd7f195662bc45c39443859e63e18b2
- pkg:maven/org.jetbrains.kotlin/kotlin-gradle-plugin-api@2.3.21,
  kotlin-gradle-plugin-api-2.3.21-gradle813.jar,
  ad58d2638ee041f6ce4e73e9782ebf528e18cf9003b1099aa7045ec958e3c195

Only exact static Maven Central HTTPS paths for the above coordinates are
requested, with no redirects. Selected Gradle cached JAR size/SHA,
the historical local SHA pin and downloaded repository bytes must all agree.
Byte mismatches block. Network/404/missing cache means NOT VERIFIED; an
offline synthetic test alone cannot establish an upstream source-byte PASS.
The CI evidence filename is gradle813-other-two-classifier-byte-evidence.json
when its actual Android workflow job executes successfully.

**IMPORTANT:** Even if exact official endpoint byte parity is verified,
publisherSignatureVerified, originAttributionVerified, licenseClosure,
noticeClosure and sbomComplete remain negative. There is no claim of
licensable binary rights, signed provenance or a complete product BOM.
Parent-POM names are untrusted metadata, not inherited license grants.
The **42 direct child POM gaps remain unresolved**.

Full legal action matrix and authoritative-document limitations:
docs/GRADLE813-TWO-CLASSIFIER-SOURCE-PARITY-20261109.md.
The Microsoft.Windows.SDK.BuildTools 10.0.26100.4654 use versus
redistribution/REDIST.TXT question is a separate blocking review.

## Selected 42 Gradle child POM legal-review queue — 9 November 2026

The partial Android Gradle build-tool evidence contains 147 selected
root/app modules. In its last confirmed CI, 42 lacked **direct child**
POM licence names: 12 child POMs not cached, 30 cached child POMs with
no direct name, 0 unreadable child POMs. This is not a determination that
the other 105 licences are approved.

The bounded independent source-POM research (selected missing children and
uncached ancestor POMs only) is reconciled into an evidence-only
42-component queue by scripts/reconcile_gradle_pom_license_gaps.py.
Its tests reject missing/duplicate selected modules, stale gap counts,
unexpected source URLs, mismatched POM identity/hashes, parent-licence
elevation, and fake approved status. Metadata may help select which exact
legal text to review next, but it never reduces the 42 legal review gaps
or inherits licences from parents.

Detailed review: docs/SELECTED-POM-LICENCE-REVIEW-QUEUE-20261109.md.
Evidence artifact when actually run by Android CI:
gradle-pom-legal-review-queue.json. All rows remain rights-NOT_VERIFIED,
the complete NOTICE/LICENSES/SBOM is missing, and release is NO-GO.

### Parent POM metadata with complex/dual licence declarations — review required

The 42-row source-reconciled queue now retains each cached parent POM
coordinate, **local-only SHA256** (or missing-state), supplier-declared
parent licence NAMES and bounded attention signals. The previous verified
Android CI reported 59 parent evidence rows; some included, for example,
CDDL/GPLv2+CE, Eclipse Distribution License 1.0, Eclipse Public License
2.0 and GNU GPLv2 with Classpath Exception supplier-name metadata.
This is **not** an inherited child licence, a determination of obligations,
or evidence that the build tools are included in a distributed APK.

Source-specific examples and exact cached POM hashes are described in
docs/PARENT-POM-LICENCE-METADATA-TRIAGE-20261109.md. The attention
signals are review prompts only; all 42 child licensing gaps, exact legal
texts, third-party rights and NOTICE/SBOM closure remain NOT VERIFIED.
No linked or embedded GPL/LGPL/MPL licence claim has been made.

## FastInfoset 1.2.16 — original Apache root LICENSE, EDL NOTICE, FIME BSD file and EE4J GPL ancestor (10 Nov 2026)

PUBLIC Android Gradle ROOT/APP **buildEnvironment** selects
pkg:maven/com.sun.xml.fastinfoset/FastInfoset@1.2.16.
It is ONE of the **42 unresolved direct child Maven POM licence metadata
review items**; this selection is NOT proof of APK/AAB/MSIX inclusion.

Original upstream eclipse-ee4j/jaxb-fi tag 1.2.16 is pinned to
commit df8b153272fd07a5e584c04a774afc8f4e67905c,
annotated tag object d7f66b8461f13509f1f3d2763533bfa5a57570ad.
Tag verified=false/unsigned; publisher cryptographic signature NOT VERIFIED.
Original root LICENSE (Apache-2.0) Git SHA1:
b5c38428d3486cd7c4f8adb0f3824a39a9987372;
root NOTICE.md (project-wide supplier EDL-1.0/SPDX BSD-3-Clause):
85121e7dd8aac65432eec604c6fe12cce454e79c;
separately FIME/LICENSE-FIME.md (BSD three-clause-style):
c739f78bc05856bfbfe35a5b76f2d4e6242cea66.
Original source child POM is Apache-2.0 header, but has no direct
Maven license element. Parent fastinfoset-project:1.2.16 supplier
POM names BOTH Apache 2.0 and EDL 1.0. The remote organization-wide
EE4J 1.0.5 parent POM lists EPLv2 and GPLv2 with Classpath Exception;
do NOT treat these distant parent names as effective linked runtime
licences without file-level and shipping-boundary review.

scripts/audit_fastinfoset1216_exact_license.py, 38 synthetic negative
tests and Android CI check exact immutable original source blobs,
Maven Central child+parent+ancestor POM and JAR vs selected Gradle cache,
bounded Maven JAR META-INF/LICENSE and META-INF/NOTICE.md bytes vs
the original Apache LICENSE/EDL NOTICE sources. FIME-specific source
applicability, chosen legal route, exact copyright notices,
publisher signature and real commercial redistribution rights remain
NOT VERIFIED. Detailed investigation:
docs/FASTINFOSET1216-EXACT-APACHE-EDL-FIME-ANCESTOR-LICENCE-REVIEW-20261110.md.

This document remains an INCOMPLETE supplier-research NOTE, not
the full third-party LICENSES/NOTICE package, not a completed
SPDX/CycloneDX SBOM or a commercial distribution permission.
42/42 selected legal review items OPEN. Product release NO-GO.

## Jakarta XML Bind API 2.3.2 — exact original EDL/BSD tag, Maven POM and JAR review (10 November 2026)

Selected PUBLIC Gradle root/app BUILD-TOOL module
pkg:maven/jakarta.xml.bind/jakarta.xml.bind-api@2.3.2 is one of
42 child POM direct metadata gaps. Its immediate parent
jakarta.xml.bind:jakarta.xml.bind-api-parent:2.3.2 declares
Eclipse Distribution License - v 1.0 (EDL) in supplier POM metadata.
Ancestor org.eclipse.ee4j:project:1.0.5 declares EPL 2.0
and GPLv2 with Classpath Exception at ORGANIZATIONAL parent level.
Do not infer effective child license or linked APK redistribution
obligations from distant supplier parent metadata.

Original 2.3.2 upstream jakartaee/jaxb-api annotated tag points at
commit 18b50028fd7dbd1305c359cd5624b1cddb1724a8 and unsigned
tag object 6e6292004b760313faf71973a3ccb578d73fe90a.
Tagged source Git blobs: LICENSE.md
6fb337cb014d5ae5d406194049b960982e307849,
NOTICE.md 5aac171d23ff9e49976751b7952759233af8a29e,
jaxb-api/pom.xml 9415ef692cc29acaa647ced0fae057d8e57e3968,
root pom.xml 979df40b6d322f23dc632bdd59c7f5121eb74fed.
The original tagged NOTICE labels EDL 1.0 and SPDX BSD-3-Clause;
its project-wide Third-party Content states None. This does
NOT prove Android/Windows release has no transitive dependencies.
The source API POM declares jakarta.activation-api dependency.

scripts/audit_jaxbapi232_exact_license.py and synthetic negative
tests/test_jaxbapi232_exact_license.py check exact source Git blobs,
Maven Central child/parent POM and JAR bytes against scoped local Gradle
cache SHA-256 and the embedded META-INF/LICENSE.md and NOTICE.md against
the original tagged source bytes. Unexpected runtime scope or forged
licensing rights fail closed; release permission is NEVER inferred
from an unsigned tag, supplier text names or byte parity.
Detailed review: docs/JAXBAPI232-EXACT-TAG-EDL-BSD-LEGAL-REVIEW-20261110.md.
All 42 child metadata reviews stay OPEN, full NOTICE/LICENSES/SBOM and
commercial redistribution rights NOT VERIFIED, product release NO-GO.

## iStack Commons Runtime 3.0.8 — exact EDL/BSD tag and JAR-embedded legal text review (9 Nov 2026)

The Gradle root/app BUILD-TOOL-only selected Maven module
pkg:maven/com.sun.istack/istack-commons-runtime@3.0.8 has no direct
child POM license name. Its parent com.sun.istack:istack-commons:3.0.8
declares Eclipse Distribution License - v 1.0; organization-wide
org.eclipse.ee4j:project:1.0.5 includes EPLv2 and GPLv2/Classpath
Exception names as unverified PARENT metadata. These are NOT an
automatic effective child licence or confirmed Android APK runtime bytes.

Original supplier tag 3.0.8 (eclipse-ee4j/jaxb-istack-commons) is
pinned to commit 5384038f6a62c7e4ed32b609fa15c796732dd3c5,
original LICENSE.md Git blob
c739f78bc05856bfbfe35a5b76f2d4e6242cea66, NOTICE.md Git blob
85121e7dd8aac65432eec604c6fe12cce454e79c.
The original tag is UNSIGNED, so publisher cryptographic provenance
NOT VERIFIED. The source has EDL v1.0 / SPDX BSD-3-Clause supplier
metadata and a project-wide third-party NOTICE. The latter is NOT
the exact downstream runtime transitive dependency inventory.

scripts/audit_istack308_exact_license.py and adversarial synthetic
tests/test_istack308_exact_license.py require source-tag Git blobs
and exact Maven Central child/parent POM + JAR bytes against the
PUBLIC selected Gradle cache hashes; compare JAR
META-INF/LICENSE.md and META-INF/NOTICE.md bytes with exact tagged
source; reject spoofed rights or package-graph scope. The scoped
JSON evidence output is only for review, NOT a full licence/NOTICE
inventory, signer proof or redistributable product release.
See docs/ISTACK308-EXACT-TAG-EDL-BSD-LEGAL-REVIEW-20261109.md.
All 42 direct child licensing review gaps remain OPEN, no release
package composition or commercial redistribution rights verified.

## Jakarta Activation API 1.2.1 — exact EDL/BSD tagged source and JAR research (9 Nov 2026)

PUBLIC Gradle root/app **build-tool selected**
pkg:maven/jakarta.activation/jakarta.activation-api@1.2.1 is
another one of the 42 unresolved child POM direct licence metadata
gaps. The immediate parent com.sun.activation:all:1.2.1 names
EDL 1.0; the distant EE4J organization parent mentions
EPLv2/GPLv2+Classpath. **Do not inherit** the organization-wide
licence names as a conclusion about this API JAR.

The original 1.2.1 supplier release tag at jakartaee/jaf-api is
pinned to commit 41bad0bd6ba821abd8652c80e8e3c50b55851da2,
annotated tag 74a1e74bf03213a0bb16e8e2392933aa47c233f3.
GitHub reports this original tag is **unsigned**. Its source
LICENSE.md has Git blob e0358f972175d83cc567fcd129cc205ea9d40ff0;
NOTICE.md has Git blob d6492f81ccce4efec1e8d03248ca64d3b26c164f;
API source POM has Git blob 09697c4589fb48882fb8ad28aaffe5d097054351.
Supplier notice labels EDL 1.0 and SPDX BSD-3-Clause; the exact
copyright/non-endorsement text and binary notices still need
human review. An unsigned Git tag is not a publisher signature.

scripts/audit_activation_api121_exact_license.py with 34 synthetic
adversarial tests checks bounded official Maven Central child/parent
POM and JAR bytes against selected LOCAL Gradle cache hashes,
compares source POM with version-pinned original source, and verifies
JAR-embedded META-INF/LICENSE.md and META-INF/NOTICE.md against
the historical upstream tagged bytes. The program fail-closes
on byte drift or scope change and retains a scoped JSON evidence file;
no result is a signed-package inventory or legal release permission.

Detailed version-specific review:
docs/JAKARTA-ACTIVATION-API121-EXACT-EDL-TAG-REVIEW-20261109.md.
Official historical tag:
https://github.com/jakartaee/jaf-api/releases/tag/1.2.1

All 42 direct child POM metadata review items, publisher-signature
verification, actual APK/AAB/MSIX runtime composition, complete
third-party NOTICE/LICENSES/SBOM, effective licence obligations and
commercial redistribution rights remain **NOT VERIFIED**.
This research does not add an E-Scanner product root LICENSE.

## JAF 1.2.0 exact release-tag and JAR-embedded licence byte crosscheck — 9 Nov 2026

PUBLIC Gradle root/app BUILD-TOOL selected
pkg:maven/com.sun.activation/javax.activation@1.2.0 is one of the **42**
unresolved direct child POM licence metadata gaps. Its Maven parent POM
com.sun.activation:all:1.2.0 lists CDDL/GPLv2+CE. The parent's supplier
licence link points to mutable GitHub master; this is **not** exact
version provenance or an approved effective child licence.

An original, immutable release-tag source was found in the archived upstream
javaee/activation JAF-1_2_0 release, commit
8f8ec08d736983c839d31a7bd98d29594e508785, LICENSE.txt Git blob
5ad62c442b336861b5832b7a8197a507b7df61f0. The full CDDL-1.1,
GPLv2 and Classpath Exception licence text and source-file header exceptions
require individual human review. Nothing here chooses CDDL or GPL,
guarantees an exception applies, or clears third-party redistribution.

scripts/audit_jaf120_exact_license.py (synthetic tests at
tests/test_jaf120_exact_license.py) checks official Maven Central exact
child/parent POM and JAR bytes against selected LOCAL Gradle cache hashes,
and compares the JAR-embedded META-INF/LICENSE.txt to exact tagged
LICENSE.txt bytes. It also checks the partial Android app/test dependency
graph has not changed to include this build-tool coordinate. A file/byte
mismatch is BLOCKED, not silently accepted. GitHub CI retains only a
scoped JSON evidence report, not a ready-to-ship licence bundle.

Official exact-tag reference:
https://github.com/javaee/activation/releases/tag/JAF-1_2_0
Versioned scope/readiness decision:
docs/JAF120-EXACT-TAG-LICENCE-BYTE-REVIEW-20261109.md.
A matching licence text, POM or JAR hash does **not** prove signed publisher
identity, actual Android APK inclusion/exclusion, SPDX/CycloneDX closure,
legal redistribution rights or a completed THIRD-PARTY LICENSES inventory.
All 42 child review items remain OPEN and product release is NO-GO.

## Windows SDK BuildTools exact NuGet archive hash vs REDIST rights — 9 November 2026

This independent PUBLIC-only build-tool evidence audit DOES NOT clear
Microsoft.Windows.SDK.BuildTools 10.0.26100.4654 for commercial
redistribution. The disposable restore-selected package has a supplier
legacy licenseUrl but NO direct nuspec licence declaration.

A bounded cache audit verifies two **different** NuGet SHA-512 domains:
raw .nupkg byte SHA-512 against its cache .nupkg.sha512; and
signature-neutral .nupkg.metadata/contentHash against project.assets.json
restore metadata. Their difference for signed nupkg is expected by NuGet's
package hash design (https://github.com/NuGet/Home/wiki/Nupkg-Metadata-File).
The exact embedded .nuspec SHA-256 is compared with the restore-extracted
.nuspec SHA-256. Archive filename evidence can identify REDIST/LICENSE
candidates, but neither their presence nor absence proves distribution
rights. The audit does not validate publisher signing identity.

Code: scripts/audit_windows_sdk_buildtools_nupkg.py;
legal boundary: docs/WINDOWS-BUILDTOOLS-EXACT-NUPKG-REDIST-REVIEW-20261109.md.
The source code, actual REDIST.TXT and applicable package-version licence
and release-payload composition still require independent review.
NOTICE/LICENSES, complete SBOM and product source LICENSE are UNVERIFIED.
No Windows installer or product runtime inclusion has been approved.

## Windows App SDK temporary restore license metadata gap — 6 November 2026

This is a **disposable build-tool compatibility probe**, not a Windows
E-Scanner application dependency or an approved release notice entry.

PUBLIC Windows App SDK 2.6.4 isolated NuGet restore runner evidence:
https://github.com/ftmstr/Embasic-E-Scanner-Build/actions/runs/42111909888

- 16 selected NuGet packages (temporary `net10.0-windows` restore only).
- 16 cached `.nuspec` files and 16 NuGet SHA-512 *metadata* values.
- 15 packages with a direct supplier `<license>` declaration.
- 1 package with **no direct** `<license>` element:
  `pkg:nuget/microsoft.windows.sdk.buildtools@10.0.26100.4654`.
- That package's supplier metadata contains legacy
  `licenseUrl=https://aka.ms/WinSDKLicenseURL`; the linked Windows
  SDK terms must be reviewed in full for build, embedding and distribution.
  A URL is NOT a licence grant or an evaluated redistributable policy.
- Source listing: https://www.nuget.org/packages/Microsoft.Windows.SDK.BuildTools/10.0.26100.4654

All selected NuGet `project.assets.json` SHA-512 values and local nuspec
SHA-256 values are **partial metadata/hash evidence only**. No independently
verified publisher signature, complete transitive license inventory,
binary-level attestation, native WinUI XAML build or device smoke is
established. **License closure, product inclusion and release remain NO-GO.**

Gradle parent POM references (where present) are also research-only metadata:
do NOT copy/infer/grant a child's license from a parent POM without reviewing
the exact legal and binary distribution boundaries. Parent evidence hashes
are local cache SHA-256, not upstream publisher provenance.

## Still missing

The PUBLIC repository's owner-approved **product LICENSE**, complete Android
and Windows direct/transitive dependency and SDK license inventory, SBOM,
THIRD-PARTY LICENSES closure, all required notices, package checksum and
signing evidence. Keep release status **NO-GO**. This partial notice does not
mark any of those gates as approved.
