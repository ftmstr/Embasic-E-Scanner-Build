# Third-party notices — REVIEW INCOMPLETE

This file records **known PUBLIC-sourced build-tool components only**. It is
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

## Still missing

The PUBLIC repository's owner-approved **product LICENSE**, complete Android
and Windows direct/transitive dependency and SDK license inventory, SBOM,
THIRD-PARTY LICENSES closure, all required notices, package checksum and
signing evidence. Keep release status **NO-GO**. This partial notice does not
mark any of those gates as approved.
