# Android clean-room toolchain and third-party candidate audit — 29 Oct 2026

**PUBLIC only. Research does not constitute legal approval, release approval
or full dependency graph validation.** PRIVATE code/history and binary
artifacts remain entirely outside this repository.

## Selected foundation build matrix (actually staged)

| Item | Candidate/pinned version | Evidence | Status |
|---|---|---|---|
| Gradle | 8.14.6 | Official release checksum reference | PINNED / ZIP verified in isolated CI |
| Android Gradle Plugin | 8.13.2 | Supports Gradle >=8.13, JDK17, API <=36.1 and Kotlin2.3 via R8 8.13.19 | SOURCE CONFIGURED; artifact license/transitives REVIEW OPEN |
| Kotlin Android Gradle plugin | 2.3.21 | Kotlin stable, Apache-2.0 source license | SOURCE CONFIGURED; fetched artifact graph REVIEW OPEN |
| JDK | 17 | AGP 8.13 compatibility | RUNNER VERIFIED / runtime terms REVIEW OPEN |
| Android compile/target SDK | 36/36 | Supported by AGP 8.13.x | CI SDK36 PRESENT; SDK Terms acceptance NOT VERIFIED |
| Android minSdk | 26 | PUBLIC clean-room product choice | SOURCE CONFIGURED |
| Gradle wrapper JAR | 8.14.6 | Official SHA-256 and exact upstream Git blob confirmed | PRESENT / HASH VERIFIED; release NOT APPROVED |
| Gradle wrapper scripts | gradlew, gradlew.bat | Exact unmodified scripts at pinned Gradle c27417f commit | PRESENT / SOURCE VERIFIED |

**Authoritative Gradle 8.14.6 SHA-256 pins:**
- gradle-8.14.6-bin.zip:
  `7988ed071b2a07900e2ec715fca15c6ab72bce6db433af301fa7fae9407bd24`
- gradle-8.14.6-wrapper.jar:
  `ad16bca46cb71bb5887c546860d93992aeee35c1fdaf4a242b0a612375d937e0`
- Source: https://gradle.org/release-checksums/
- Verification: https://docs.gradle.org/current/userguide/gradle_wrapper.html
- Official Gradle Build Tool source license: Apache-2.0
  https://docs.gradle.org/current/userguide/licenses.html
- AGP 8.13 compatibility:
  https://developer.android.com/build/releases/agp-8-13-0-release-notes
- Kotlin licensing: Apache-2.0 for its source distribution, with separate
  upstream third-party notices to review:
  https://kotlinlang.org/docs/faq.html
  https://github.com/JetBrains/kotlin/tree/master/license


## Update: upstream verified build-tool wrapper, 2026-10-29

The public Gradle 8.14.6 JAR (44,309 bytes) was independently SHA-256
verified against the official release checksum and then staged with its
upstream Git blob SHA identical. The executable Unix and Windows wrapper
scripts and Gradle LICENSE were copied without modification from immutable
public upstream commit `c27417f274bd1cf2f36e1f93d54e3de840d54e43`.
See `docs/GRADLE-WRAPPER-PROVENANCE-20261029.md` and
`THIRD-PARTY-NOTICES.md` for provenance, hash evidence and Apache-2.0
attribution. The Gradle v8.14.6 source tag itself contains a different
bootstrap JAR; do not trust that tag as a released wrapper. The original
PUBLIC Android wrapper CI now validates the official JAR SHA-256 and
pinned Gradle ZIP SHA-256 before invoking the script.

## Update: JUnit test-only license boundary

A minimal `junit:junit:4.13.2` JUnit4 runner was introduced through
`testImplementation` to require actual JVM test case execution rather
than a silent NO-SOURCE task. Its Maven POM declares EPL-1.0 (not
permissive) and `org.hamcrest:hamcrest-core:1.3` as a compile
transitive, with Hamcrest New BSD license. These two modules must remain
isolated to **JVM local tests** and absent from debug/release APK
runtime dependencies. See:
- https://central.sonatype.com/artifact/junit/junit/4.13.2
- https://central.sonatype.com/artifact/org.hamcrest/hamcrest-core/1.3

The Android CI now checks JUnit XML case count >0 and will audit the
debugRuntimeClasspath against debugUnitTestRuntimeClasspath; it fails
closed on missing test output or runtime leakage. This is a documented
test-scope boundary, not owner-approved EPL runtime redistribution and
not a completed SBOM or transitive copyright audit. The project's own
root LICENSE remains to be selected by the rights holder.

## Proposed, NOT ADDED runtime dependencies

The PUBLIC Android foundation intentionally avoids adding these libraries
until direct and transitive dependencies, artifacts, licenses, maintenance,
platform compatibility and advertising data flow are reviewed.

| Library | Candidate only | Source/license research | Gate |
|---|---|---|---|
| Compose compiler | Kotlin `org.jetbrains.kotlin.plugin.compose` 2.3.21 | Compiler plugin version equals Kotlin; Apache-2.0 source with upstream notices | NOT ADDED; transitive audit |
| Compose Material 3 | Compose BOM 2025.10.00 (conservative pre-API37 baseline) | Google Android Compose setup; AndroidX generally Apache-2.0 | NOT ADDED; inspect BOM and transitive metadata |
| AndroidX Activity Compose | 1.11.0 | Android developer Activity notes (built for API36) | NOT ADDED |
| CameraX | 1.5.3 | Official AndroidX CameraX release notes and AOSP Apache-2.0 source headers | NOT ADDED; complete artifact/transitive review |
| OCR, imaging, PDF, ads | No version approved | No provider/product selected | **BLOCKED**, no implied license |

Why not adopt the latest Compose BOM immediately? Starting with
Compose 1.12.0, Google documents an API37 + AGP9 requirement. AGP8.13
supports API36.1; mixing them without resolving SDK and plugin compatibility
is not an admissible release baseline. This is a candidate matrix, not a
verified compatibility or compile claim for non-added libraries.

Sources:
- https://developer.android.com/develop/ui/compose/setup-compose-dependencies-and-compiler
- https://developer.android.com/jetpack/androidx/releases/camera
- https://developer.android.com/jetpack/androidx/releases/activity
- https://developer.android.com/build/kotlin-support
- https://developer.android.com/studio/terms

## Licensing and provenance decisions pending

1. **Product source license:** PUBLIC repository has no owner-approved root
   LICENSE; public visibility alone grants no license to third-party reusers.
   Ask rights holder to select whether/how to license it. Do not invent
   blanket Apache-2.0 ownership.
2. **Android SDK:** Google SDK Terms grant a limited SDK-use license, not a
   permissive right to redistribute the SDK.
3. **Android Gradle Plugin:** published through Google tooling channels;
   artifact/subcomponent licensing and transitive graph require independent
   audit before redistribution/release.
4. **Kotlin:** Apache-2.0 project source does not automatically establish
   license of every transitive artifact or compiler tool.
5. **Wrapper:** no JAR imported or approved. Text-only checksum expectation
   cannot authenticate a missing JAR. Isolated CI ZIP SHA verification
   is not a release wrapper acceptance.
6. **SBOM/NOTICE:** require actual resolved dependency graph and full
   per-artifact license inventory. No fabricated compliance claim.
7. **Privacy:** advertising provider must be outside scan domain and must
   have zero access to documents, OCR, pairing secrets and fingerprints.

## Next acceptance evidence (NOT RUN unless linked)

- Obtain owner-approved license and written clean-room provenance; review
  all direct/transitive artifacts, licensing, Android SDK Terms and notices.
- Reproduce Android `:app:assembleDebug :app:lintDebug` with verified
  Gradle ZIP; separately run real JVM/instrumented tests and device smoke.
- Recreate official Gradle wrapper scripts/JAR from a verified trusted
  toolchain, verify expected JAR SHA before commit and execute; never
  shortcut the original fail-closed wrapper workflow.
- Validate Compose/CameraX license and SDK compatibility before adding
  functional scanning features or declaring parity.
- Produce SBOM, NOTICE/LICENSES and package hashes before release.

**Release decision: NO-GO; feature parity and package/runtime verification OPEN.**
