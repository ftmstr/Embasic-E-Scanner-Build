# PUBLIC Gradle source-byte parity — 7 November 2026, corrected follow-up

**Scope: four NEW Maven Central build-tool JARs with missing direct child POM license names.
Not an Android/Windows scanner release, publisher attestation or a complete 147-module SBOM.**

## Correction and source-of-truth

The initial batch at `5c751005c7b84500d65c673a83c0b076727cf330`
unintentionally duplicated four JARs already verified in a preceding tour:
Guava, Protobuf Java, Commons IO, and SLF4J API. Those checks remained valid
but provided **zero new module coverage**. The mistake was detected and
corrected on the same PUBLIC fix branch, without changing main or PR #1.

The corrected batch targets four **different** resolved modules whose local
child POM has no direct license name. No parent POM is treated as a license grant.

- Fix commit `5fd685e80ff45e36094687824f990498e6e92d40`: four distinct PURL allowlist entries and direct-license-gap identity check.
- Test commit `51799eb4c95051373aabb5ade80f03ff4bcada88`: two additional regression cases (total 17) prevent future duplicate sampling and unexpected licensing-status escalation.
- CI commit `309fb328cc7439e4c549fa5ed65effab6c6f91c7`: exact selected PURLs and missing direct-license metadata enforced as in-CI assertions.

## Real corrected PUBLIC CI

- Run https://github.com/ftmstr/Embasic-E-Scanner-Build/actions/runs/42365165688
- Job `128381581463`, **completed/success**.
- `17/17` synthetic security tests PASS; Android JUnit `6/6`, failures/errors/skips 0.
- Selected four new cached JAR SHA256 + byte sizes matched official Maven Central HTTPS bytes exactly: `4/4` PASS, `notSourceVerified=0`.
- Evidence JSON `gradle-central-buildtool-jar-byte-evidence.json` in CI artifact
  `android-foundation-dependency-evidence` ID `13570864748`
  (14-day retention; ZIP 31,513 bytes).

| Selected Maven artifact / distinct module | Official/local SHA-256 |
|---|---|
| `com.google.guava:failureaccess:1.0.2` | `8a8f81cf9b359e3f6dfa691a1e776985c061ef2f223c9b2c80753e1b458e8064` |
| `com.google.protobuf:protobuf-java-util:3.25.5` | `dacc58b2c3d2fa8d4bddc1acb881e78d6cf7c137dd78bc1d67f6aca732436a8d` |
| `com.google.jimfs:jimfs:1.1` | `c4828e28d7c0a930af9387510b3bada7daa5c04d7c25a75c7b8b081f1c257ddd` |
| `com.google.auto.value:auto-value-annotations:1.6.2` | `b48b04ddba40e8ac33bf036f06fc43995fc5084bd94bdaace807ce27d3bea3fb` |

All official-source URLs use the static allowlisted
`https://repo.maven.apache.org/maven2/<group path>/<artifact>/<version>/<artifact>-<version>.jar`.
Exact URL, PURL, SHA-256 and SOURCE_BYTES_MATCH_LOCAL status are in the CI log.

## Classifier/origin/license boundary

The tool accepts only exact non-classifier JAR filenames and coordinate
patterns in the reviewed allowlist. Other cached classifier variants remain
`unreviewedJarVariants` and do NOT obtain a fabricated source SHA match.
Mismatching official bytes raise an AuditError (fail closed); missing local
JARs, 404s and transport errors remain explicit gaps. There is no network
fallback to untrusted hosts or redirect following.

Corrected data is **remote byte parity, not signed publisher provenance**:
`publisherSignatureVerified=false`,
`originAttributionVerified=false`, `licenseClosure=NOT_VERIFIED`,
`noticeClosure=NOT_VERIFIED`, `sbomComplete=false`,
`releaseApproved=false`.

This turn increases disjoint sampled Gradle build-tool JAR modules from six
(previous 2 pinned AGP/KGP and 4 Maven Central transitive modules) to
**10 distinct sampled modules** out of 147 selected modules. It is NOT a
complete binary provenance measure for all 147, and is separate from four
Android debug runtime/JUnit-test JARs verified earlier. Some selected modules
have no standard JAR; do not infer completeness from 10/147.

POM direct license names remain 105 of 147, with **42 direct metadata gaps**
(12 POM not cached, 30 no direct license names). The four newly checked modules
belong to the no-direct-name group. Source POMs, parent POM names, and their
metadata are unapproved claims pending applicable third-party licenses/terms
and transitive obligations. Other open gates: publisher signature, full
NOTICE/LICENSES/SPDX/CycloneDX SBOM, rights-holder-approved PUBLIC product
root LICENSE, Windows SDK BuildTools redistributables and actual linked
Android/Windows runtime composition.

Windows App SDK 2.6.4 is still only a disposable .NET 10 Windows NuGet restore
probe (16 packages; 15 with direct supplier license metadata). The package
`Microsoft.Windows.SDK.BuildTools@10.0.26100.4654` lacks a direct nuspec
license element, citing `https://aka.ms/WinSDKLicenseURL`. No legal closure
or redistributed Windows executable/app asset has been verified.

**PR #1 remains OPEN/DRAFT/BLOCKED FOR MERGE. PRIVATE untouched; PUBLIC main
unmodified. Android CameraX, Windows WinUI3, QR/TLS, local OCR/searchable PDF,
staged atomic export, shared golden fixtures and signed package acceptance
remain NOT VERIFIED. RELEASE NO-GO.**
