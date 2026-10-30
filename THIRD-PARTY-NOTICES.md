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

## Still missing

The PUBLIC repository's owner-approved **product LICENSE**, complete Android
and Windows direct/transitive dependency and SDK license inventory, SBOM,
THIRD-PARTY LICENSES closure, all required notices, package checksum and
signing evidence. Keep release status **NO-GO**. This partial notice does not
mark any of those gates as approved.
