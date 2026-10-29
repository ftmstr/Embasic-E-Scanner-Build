# Embasic E-Scanner Android — independent PUBLIC foundation

Status: **CLEAN-ROOM FOUNDATION ONLY / NO-GO RELEASE**. This source was
authored afresh for the PUBLIC ftmstr/Embasic-E-Scanner-Build repository.
No PRIVATE Git history, APK, proprietary scan, signing key, customer
asset, or proprietary runtime dependency was imported. The sole imported
binary is the public upstream Gradle build-tool wrapper with verified SHA,
source Git blob identity and copied upstream license; see
`docs/GRADLE-WRAPPER-PROVENANCE-20261029.md`.

## Current Kotlin build inputs

- Android Gradle Plugin 8.13.2, Kotlin Android plugin 2.3.21, JDK 17.
- Official Gradle **8.14.6** binary-only ZIP. Published SHA-256:
  `7988ed071b2a07900e2ec715fca15c6ab72bce6db433af301fa7fae9407bd24`.
  The exact value is in `gradle/wrapper/gradle-wrapper.properties`.
- Published Gradle 8.14.6 wrapper JAR SHA-256:
  `ad16bca46cb71bb5887c546860d93992aeee35c1fdaf4a242b0a612375d937e0`.
  The exact upstream JAR and unmodified `gradlew` / `gradlew.bat` scripts
  are committed and verified against the public Gradle 8.14.6 source commit
  `c27417f274bd1cf2f36e1f93d54e3de840d54e43`. A SHA text file alone
  would NOT have been enough.
- `compileSdk=36`, `targetSdk=36`, `minSdk=26` and Java target 17.
- `:app` has one `Activity` that displays an explicit non-release message.
  There are **no camera, storage or network permissions**.
- Third-party *production runtime* libraries for Compose/Material 3, CameraX,
  OCR, networking, monetization and export are **not included** pending
  direct/transitive licensing review. JUnit 4.13.2 (EPL-1.0) and its
  Hamcrest Core 1.3 (BSD) dependency are **testImplementation only**;
  CI must prove neither appears in the production runtime graph.
  This is not a scanner and not platform feature parity.

## Two distinct CI gates

1. Existing `.github/workflows/android-build.yml` now checks the committed
   executable `gradlew`, the official JAR SHA-256 and the pinned distribution
   checksum before executing. It runs `testDebugUnitTest lintDebug assembleDebug`,
   rejects NO-SOURCE test runs, and audits test-only dependency isolation.
   GitHub CI run/job/step/log success must be checked separately.
2. `.github/workflows/android-cleanroom-compile.yml` separately fetches
   Gradle's official 8.14.6 distribution via HTTPS, verifies the ZIP
   against the independently sourced published SHA-256 **before executing
   it**, checks that Android SDK 36 is present without accepting new SDK
   terms, then runs an **unsigned** `:app:assembleDebug :app:lintDebug`.
   Passing this is compile/lint evidence only; it is not evidence of
   JUnit execution, instrumented tests, runtime, device smoke,
   user features, release signing, or full licenses.

## Official sources and unresolved license gates

- Gradle 8.14.6 distribution/wrapper digests:
  https://gradle.org/release-checksums/
- Gradle wrapper verification and regeneration guidance:
  https://docs.gradle.org/current/userguide/gradle_wrapper.html
- Android Gradle Plugin 8.13 compatibility/JDK/API:
  https://developer.android.com/build/releases/agp-8-13-0-release-notes
- Kotlin source licensing:
  https://kotlinlang.org/docs/faq.html
- Android SDK Terms (not equivalent to a permissive code license):
  https://developer.android.com/studio/terms
- Dependency candidates, WITHOUT importing them, are documented in
  `docs/ANDROID-TOOLCHAIN-LICENSE-RESEARCH-20261029.md`.

The product license, direct and transitive dependencies, Android SDK Terms,
SBOM, complete NOTICE, reproducible artifact identity, Android on-device smoke,
privacy requirements, signed APK/AAB and rollback remain open **release
gates**. Never equate a CI job's success with release certification.
