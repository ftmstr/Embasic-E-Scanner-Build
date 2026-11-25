# PUBLIC iStack Commons Runtime 3.0.8 exact tag EDL/BSD and Maven JAR licence review — 9 November 2026

Only PUBLIC ftmstr/Embasic-E-Scanner-Build; branch fix/pdf-fixture-selftest-20261018, PR #1 OPEN/DRAFT. PRIVATE/main/merge/force and unapproved root product LICENSE remain out of scope.

## Child versus inherited POM supplier metadata

Selected Gradle root/app buildEnvironment module:
pkg:maven/com.sun.istack/istack-commons-runtime@3.0.8.
Its direct child Maven POM has no license-name declaration, and is
one of the 42 selected unreviewed direct child metadata gaps.

Immediate parent com.sun.istack:istack-commons:3.0.8 declares
Eclipse Distribution License - v 1.0. Cached parent POM SHA256
a0f0517e8512f0fbcc7b8295c12f6566a3d0c2d86d655639dc662ef8c0c7ebe5.
An organizational ancestor org.eclipse.ee4j:project:1.0.5 declares
EPL-2.0 and GPLv2 with the Classpath Exception in POM metadata.
Cached organizational POM SHA256
916b4794d8d8220a59a3fdf6a64dbe794aeb23395e888b81ae36a9b5a2c591a6.

None of these parent names automatically constitutes an effective
child-file license, a GPL linking obligation, a classpath exception
for this child, an elected license or a legally reviewed redistribution grant.

## Original source version, pinned to peeled commit

Upstream eclipse-ee4j/jaxb-istack-commons annotated tag 3.0.8:
Git tag object f7e3de724c9c87fe7bdb59acc4b2588508907e22,
peeled commit 5384038f6a62c7e4ed32b609fa15c796732dd3c5.
GitHub's upstream tag verification reported unsigned / NOT VERIFIED.
Immutable pinned Git source blobs at this commit:
- LICENSE.md: c739f78bc05856bfbfe35a5b76f2d4e6242cea66.
- NOTICE.md: 85121e7dd8aac65432eec604c6fe12cce454e79c.
- istack-commons/runtime/pom.xml:
  3900bb38f6cea873fcfca9cb85ea867fd4d9193a.
- istack-commons/pom.xml:
  1bf55a0f4655d0dd63187f1b905e48764c623c59.

The source LICENSE.md contains BSD three-clause-style attribution,
non-endorsement and disclaimer text. The supplier NOTICE.md and
POM source headers reference EDL v1.0 and SPDX BSD-3-Clause. This
is vendor-supplied documentary context, not automatic legal clearance.

The upstream NOTICE includes a project-wide third-party inventory and
cryptography note, NOT proof that all those packages ship inside the
individual istack-commons-runtime JAR. The runtime source POM declares
jakarta.activation-api and junit dependencies. Their true effective
scopes, transitive chain, actual release binary inclusion and applicable
copyright notices remain subject to separate resolved graph and
package-level evidence, even with the prior Activation API 1.2.1 review.

## Exact seven-source CI gate

Official Maven coordinates:
https://repo.maven.apache.org/maven2/com/sun/istack/istack-commons-runtime/3.0.8/istack-commons-runtime-3.0.8.pom
https://repo.maven.apache.org/maven2/com/sun/istack/istack-commons-runtime/3.0.8/istack-commons-runtime-3.0.8.jar
https://repo.maven.apache.org/maven2/com/sun/istack/istack-commons/3.0.8/istack-commons-3.0.8.pom

Four other official raw sources are pinned to the original
commit SHA, not to a mutable branch or unsigned moving tag.

New scripts/audit_istack308_exact_license.py checks actual PUBLIC
Gradle root/app plugin cache-selected child POM/JAR SHA256 and byteSize
against Maven Central, parent POM cached SHA256 versus Maven, all four
original-source Git blob identities, source POM versus published Maven
POM bytes, exact child/parent coordinate and supplier EDL metadata, and
the Maven JAR's embedded META-INF/LICENSE.md and META-INF/NOTICE.md
byte equality with exact source-tag file bytes.

Strict allowlist of seven URLs, HTTPS only, no redirects, bounded byte
counts, bounded ZIP members and unpacked bytes, rejected path traversal,
duplicate/symlink/missing JAR legal file, altered parent or legal text,
forged approvals for ANY of 42 selected legal review rows and unexpected
new inclusion in the independently resolved Android debug app/test
configuration graphs. Scope is still PARTIAL. The absence of the
coordinate from those graphs does not prove absence from a signed
APK/AAB/MSIX release payload.

Tests at tests/test_istack308_exact_license.py are clean generated
negative fixtures. Exact CI success is required before saying remote
Maven/source/JAR bytes actually match; an upstream difference is
BLOCKED, never inferred away. Scoped output file:
istack308-exact-source-legal-evidence.json. It is NOT a complete
third-party licence, publication authority, NOTICE bundle or
SPDX/CycloneDX SBOM.

## Independent release blockers

Exact source copyright/NOTICE reproduction, source headers, all
parent-versus-child and chosen licence obligations, binary
redistribution, full runtime/transitive graph and publisher signatures
remain NOT VERIFIED. All 42 direct child legal review items remain OPEN.
The Microsoft.Windows.SDK.BuildTools 10.0.26100.4654 exact EULA/REDIST
file-list/shipping rights remain a separate NO-GO. A NuGet package hash
or missing REDIST-named file inside its ZIP does not grant rights.
Owner approval is required before adding the product root LICENSE.

Native 0/41, platform foundation 3/6, structural 4/5,
release 0/8. Conditional 31 December 2027 is a planning assumption,
not a production delivery promise. No legal or native release gates
are deemed complete by this research.
