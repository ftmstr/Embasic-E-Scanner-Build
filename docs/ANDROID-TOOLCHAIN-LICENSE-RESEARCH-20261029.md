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
| Gradle wrapper JAR | 8.14.6 | Expected official SHA-256 recorded | **NOT PRESENT / NOT VERIFIED** |
| Gradle wrapper script | gradlew | Must be generated from trusted Gradle distribution then independently reviewed | **NOT PRESENT / BLOCKED** |

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
