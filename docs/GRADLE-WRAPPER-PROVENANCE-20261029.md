# Verified Gradle Wrapper provenance — PUBLIC 2026-10-29

Purpose: preserve a reproducible, inspectable Gradle wrapper for the
independently authored PUBLIC Android foundation. No PRIVATE content,
preexisting user document, credential, signing asset or proprietary binary
was imported.

## Origin and immutable input

Source: official public `gradle/gradle` repository, immutable commit
`c27417f274bd1cf2f36e1f93d54e3de840d54e43` ("Update to Gradle 8.14.6").
Official upstream repository license copied unmodified to
`third_party/gradle-wrapper/LICENSE`; Gradle script headers retain their
original Apache License 2.0 attribution.

| PUBLIC path | Official Git blob SHA (same bytes) | Mode |
| --- | --- | --- |
| android/gradle/wrapper/gradle-wrapper.jar | 02f06ab2a396743f0052e4328b0e5ac2cdd8b3d2 | 100644 |
| android/gradlew | 0f14772e0e50ffe504fa3be1a869e6281b09ccd1 | 100755 |
| android/gradlew.bat | 8de1053a1f921b9ac5910187e2f99fdaa774f81a | 100644 |
| third_party/gradle-wrapper/LICENSE | 7cf0e053a08e1d98601c657ad95b161142b56fd4 | 100644 |

The downloaded-from-public-upstream binary JAR was decoded and SHA-256 hashed
**before** creating the PUBLIC Git blob. Its length was 44,309 bytes.
Actual SHA-256:
`ad16bca46cb71bb5887c546860d93992aeee35c1fdaf4a242b0a612375d937e0`.
This equals the independently published Gradle 8.14.6 wrapper JAR checksum:
https://gradle.org/release-checksums/

Gradle 8.14.6 binary ZIP expected SHA-256:
`7988ed071b2a07900e2ec715fca15c6ab72bce6db433af301fa7fa7e9407bd24`.
`android/gradle/wrapper/gradle-wrapper.properties` requires this exact value.

**Important upstream distinction:** The `v8.14.6` tag includes an older
bootstrap `gradle-wrapper.jar` with a different SHA-256. Upstream Gradle
issue #39471 documents this and identifies the published wrapper inside the
Gradle 8.14.6 binary distribution. We explicitly sourced the matching
`release8x` source commit instead of blindly trusting the tag:
https://github.com/gradle/gradle/issues/39471

## Trust and CI requirements

1. Run PUBLIC preflight: exact official JAR and distribution hashes required,
   not merely an arbitrary self-consistent 64-hex value.
2. Run wrapper-required Android workflow and independently inspect job steps,
   exit codes and logs, including actual Gradle assemble/lint/JVM tests.
3. Never allow a PR to replace the binary unless SHA-256 is verified against
   a documented independently trusted upstream checksum.
4. Repeat dependency license and provenance review before any new plugin or
   library; no automatic PRIVATE binary migration.
5. Wrapper presence/build PASS proves no WinUI/CameraX/Compose/OCR/PDF parity,
   signed APK/AAB, production security acceptance, or completed licenses.

Reference: https://docs.gradle.org/current/userguide/gradle_wrapper.html
Release gate: **NO-GO**. Product LICENSE and full SBOM still absent.
