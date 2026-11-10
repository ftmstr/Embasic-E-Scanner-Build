# PUBLIC Jakarta XML Bind API 2.3.2 exact tag EDL/BSD and Maven JAR licence review — 10 November 2026

Only PUBLIC ftmstr/Embasic-E-Scanner-Build; branch fix/pdf-fixture-selftest-20261018, PR #1 OPEN/DRAFT. PRIVATE/main/merge/force and unapproved root product LICENSE remain out of scope.

## Child versus inherited POM supplier metadata

Selected Gradle root/app buildEnvironment module:
pkg:maven/jakarta.xml.bind/jakarta.xml.bind-api@2.3.2.
Its direct child Maven POM has no license-name declaration, and is
one of the 42 selected unreviewed direct child metadata gaps.

Immediate parent jakarta.xml.bind:jakarta.xml.bind-api-parent:2.3.2 declares
Eclipse Distribution License - v 1.0. Cached parent POM SHA256
15a55b7d537c9f9970aead28d2af97c059f65ff6102f76bbd29f1247dd8a6dfb.
An organizational ancestor org.eclipse.ee4j:project:1.0.5 declares
EPL-2.0 and GPLv2 with the Classpath Exception in POM metadata.
Cached organizational POM SHA256
916b4794d8d8220a59a3fdf6a64dbe794aeb23395e888b81ae36a9b5a2c591a6.

None of these parent names automatically constitutes an effective
child-file license, a GPL linking obligation, a classpath exception
for this child, an elected license or a legally reviewed redistribution grant.

## Original source version, pinned to peeled commit

Upstream eclipse-ee4j/jaxb-jakarta.xml.bind-api-parent annotated tag 2.3.2:
Git tag object 6e6292004b760313faf71973a3ccb578d73fe90a,
peeled commit 18b50028fd7dbd1305c359cd5624b1cddb1724a8.
GitHub's upstream tag verification reported unsigned / NOT VERIFIED.
Immutable pinned Git source blobs at this commit:
- LICENSE.md: 6fb337cb014d5ae5d406194049b960982e307849.
- NOTICE.md: 5aac171d23ff9e49976751b7952759233af8a29e.
- jakarta.xml.bind-api-parent/jaxb-api/pom.xml:
  9415ef692cc29acaa647ced0fae057d8e57e3968.
- jakarta.xml.bind-api-parent/pom.xml:
  979df40b6d322f23dc632bdd59c7f5121eb74fed.

The source LICENSE.md contains BSD three-clause-style attribution,
non-endorsement and disclaimer text. The supplier NOTICE.md and
POM source headers reference EDL v1.0 and SPDX BSD-3-Clause. This
is vendor-supplied documentary context, not automatic legal clearance.

This upstream NOTICE's Third-party Content section says "None"; that is a
supplier project declaration, NOT proof that the final E-Scanner APK/MSIX
contains no transitive components. The API source POM declares a direct
jakarta.activation-api dependency; its resolved scope, exact version and
redistributed binary notices must be checked separately. The prior
Jakarta Activation API 1.2.1 tagged text research is not a complete
transitive runtime or licensing clearance.

## Exact seven-source CI gate

Official Maven coordinates:
https://repo.maven.apache.org/maven2/jakarta/xml/bind/jakarta.xml.bind-api/2.3.2/jakarta.xml.bind-api-2.3.2.pom
https://repo.maven.apache.org/maven2/jakarta/xml/bind/jakarta.xml.bind-api/2.3.2/jakarta.xml.bind-api-2.3.2.jar
https://repo.maven.apache.org/maven2/jakarta/xml/bind/jakarta.xml.bind-api-parent/2.3.2/jakarta.xml.bind-api-parent-2.3.2.pom

Four other official raw sources are pinned to the original
commit SHA, not to a mutable branch or unsigned moving tag.

New scripts/audit_jaxbapi232_exact_license.py checks actual PUBLIC
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

Tests at tests/test_jaxbapi232_exact_license.py are clean generated
negative fixtures. Exact CI success is required before saying remote
Maven/source/JAR bytes actually match; an upstream difference is
BLOCKED, never inferred away. Scoped output file:
jaxbapi232-exact-source-legal-evidence.json. It is NOT a complete
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
