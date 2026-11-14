# JAF 1.2.0 exact-tag licence review — PUBLIC BUILD-TOOL evidence only (9 Nov 2026)

**Disposition: NO EFFECTIVE CHILD LICENCE ELECTION / NO REDISTRIBUTION APPROVAL.**
PUBLIC repo ftmstr/Embasic-E-Scanner-Build; PR #1 stays OPEN/DRAFT.
No PRIVATE, main, merge, force or owner-unapproved root product LICENSE.

## Exact upstream identification

1. Exact child Maven POM:
   https://repo.maven.apache.org/maven2/com/sun/activation/javax.activation/1.2.0/javax.activation-1.2.0.pom
   and same basename .jar.
2. Exact parent POM:
   https://repo.maven.apache.org/maven2/com/sun/activation/all/1.2.0/all-1.2.0.pom
   Child POM contains no direct licences element; parent supplier metadata
   names CDDL/GPLv2+CE. Parent metadata points to **moving** GitHub master.
   A moving branch is not a versioned licence evidence source.
3. Archived original javaee/activation **JAF 1.2.0 Final Release**:
   https://github.com/javaee/activation/releases/tag/JAF-1_2_0 ;
   tag commit 8f8ec08d736983c839d31a7bd98d29594e508785 .
   Exact upstream tagged licence file:
   https://github.com/javaee/activation/blob/JAF-1_2_0/LICENSE.txt
   Git blob SHA-1 5ad62c442b336861b5832b7a8197a507b7df61f0 .
   A Git blob SHA identifies tagged repository content; it is not an
   independently verified publisher signature.

The tagged licence document contains Common Development and Distribution
License Version 1.1, GNU GPL Version 2 and an Oracle Classpath Exception.
**File-level exceptions require an explicitly designated source-file
header:** do not assert that every file or any E-Scanner binary is
unconditionally exempt. A supplier's dual-option licence declaration is
not a chosen licence option, a reviewed exception or a release grant.

## Independent exact byte evidence gate

scripts/audit_jaf120_exact_license.py runs only after the actual PUBLIC
CI Gradle root/app plugin buildEnvironment inventory, the 42-child legal
review queue, and Android app/test partial resolved configuration graph.
It fetches exactly four bounded HTTPS sources without redirects: exact
child POM, exact parent POM, exact Maven JAR, pinned tag LICENSE.txt.
It compares child POM/JAR byte SHA-256 and size with local Gradle cache;
parent POM bytes with LOCAL parent cache SHA-256; exact-tag LICENSE bytes
against Git blob identity; and JAR META-INF/LICENSE.txt against the
exact-tag licence BYTES. It never copies full licence text into the
PUBLIC repository or claims upstream publisher signature verification.

Malformed XML, wrong POM coordinate/version/parent, unexpected supplier
licence, ZIP traversal, duplicate, symlink, decompression bounds,
missing licence text, tag drift, Maven/local SHA mismatch and sudden
Android app/test runtime inclusion fail-closed. Synthetic fixtures
exercise malicious input with no proprietary UYAP or product data.
Scoped artifact output: jaf120-exact-source-license-evidence.json;
this is NOT a finished license inventory, NOTICE or SPDX/CycloneDX SBOM.

## Build-tool versus actual runtime boundary

The exact Maven coordinate is selected by Gradle root/app
buildEnvironment, not proven to be an Android APK/AAB dependency.
The current independently resolved Android debugRuntimeClasspath and
debugUnitTestRuntimeClasspath graphs do not establish a complete
release package inventory; an observed new inclusion of this JAF
coordinate requires renewed file-level rights assessment.
Whether the actual dependency is copied into an Android runtime, a
Windows MSIX or another release payload remains NOT VERIFIED
without a signed binary inventory. This audit never assumes a
parent POM licence is the child effective licence.

## Exact legal review and unresolved distribution tasks

Review actual tagged source file headers; the applicable CDDL v1.1 or
GPLv2 + Classpath Exception option, any option election, exception
file scope, source availability, copyright/NOTICE obligations, modified
files and redistributed JAR. Distinguish build-only test execution from
shipping any bytes in an APK/AAB/MSIX. Do not conclude legal
redistribution rights solely from tag, Maven source parity or parent POM.

Separate legal gate: Microsoft.Windows.SDK.BuildTools
10.0.26100.4654 has no direct NuGet nuspec licence. Its legacy pointer,
official ZIP hash, and zero REDIST candidate filenames inside this ZIP
do not establish version-specific EULA/authoritative REDIST file list
or Windows installer per-file commercial redistribution rights.

42/42 child legal review gaps remain OPEN. Native 0/41, platform
foundation 3/6, structural 4/5, release 0/8. Root product LICENSE
requires explicit owner approval. Commercial release NO-GO.
