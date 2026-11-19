# JSpecify 1.0.0 — exact Maven / tagged LICENSE source review (19 November 2026)

PUBLIC scope only: ftmstr/Embasic-E-Scanner-Build, Draft PR #1,
fix/pdf-fixture-selftest-20261018. This is one observed member of the
89 still-missing Android resolved NOTICE rows, not a waiver of the other
88 nor the separate 42 Gradle plugin child-POM review gaps. No Android
or Windows app logic, dependency version, or root LICENSE changed.

## Selected, observed Gradle coordinate

- Actual 19-Nov PUBLIC Android PR CI run 44572276040 and push run 44572260680,
  exact SHA 48befc60d424b4722ccfcaa2e37d9b2c0a5e69ab, reported 89
  missing resolved Maven NOTICE rows including
  pkg:maven/org.jspecify/jspecify@1.0.0 (found 0).
- debugRuntimeClasspath and debugUnitTestRuntimeClasspath Gradle reports
  are parsed by the already strict resolved_graph function first. A JAR
  in Gradle cache is NOT evidence of APK/AAB inclusion.
- Official JSpecify release v1.0.0 pinned public GitHub tag commit:
  b2a10e14bb81c1b7cb6e488c112fe55cb2218d7d
  Tagged LICENSE file exact Git blob SHA-1:
  d645695673349e3947e8e5ae42332d0ac3164cd7
  The tag's publisher cryptographic signature is NOT VERIFIED.

## Three fixed HTTPS sources and strict evidence boundaries

1. Maven Central exact POM:
   https://repo.maven.apache.org/maven2/org/jspecify/jspecify/1.0.0/jspecify-1.0.0.pom
   Require exact group/artifact/version and direct supplier-declared Apache-2.0
   license NAME, record SHA-256 and source byte length; POM claim is NOT grant.
2. Maven Central exact JAR:
   https://repo.maven.apache.org/maven2/org/jspecify/jspecify/1.0.0/jspecify-1.0.0.jar
   Require bounded ZIP, JSpecify annotation classes, and same SHA-256 and byte
   size as Gradle's exact local resolved JAR. Record embedded legal filename
   list; no embedded-license text byte parity is claimed.
3. GitHub tagged immutable LICENSE:
   https://raw.githubusercontent.com/jspecify/jspecify/b2a10e14bb81c1b7cb6e488c112fe55cb2218d7d/LICENSE
   Require Git blob SHA-1 equality to the independently checked tagged GitHub
   LICENSE blob and Apache License Version 2.0 text. Record LICENSE SHA-256.

The new bounded script scripts/audit_jspecify100_source_review.py rejects
arbitrary remote URLs, redirects, missing/ambiguous local cache artifacts,
unsafe symlinks, changed POM, incorrect ZIP classes and signature/byte
mismatches. The tests/test_jspecify100_source_review.py synthetic regressions
cover those failure paths and do NOT represent verified upstream source bytes.

The new workflow evidence step is after the existing fail-closed NOTICE
step and is set to run when NOT cancelled, even after an intentional NOTICE
failure. The 14-day android-jspecify100-source-evidence upload contains
bounded source hashes or an explicit NOT_VERIFIED blocker. There is no
bypass or license-approval override; Android Foundation remains FAILURE
while the 89 NOTICE entries are missing.

## Current verification and release gates

This static document describes the verification mechanism. Before exact-HEAD
CI downloads official POM/JAR/LICENSE, the remote SHA-256 and Gradle byte
comparison remain NOT VERIFIED. A PASS in a synthetic regression is not
evidence of successful live official-source transport.

Even with complete exact source bytes: publisher signature, redistribution
rights, embedded LICENSE/NOTICE legal text, APK runtime inclusion, full
Android NOTICE/SBOM, separate 42 plugin child POM reviews, Android SDK
terms, and Windows App SDK REDIST remain NOT VERIFIED.

No physical Android DocumentsProvider JPG/PNG / genuine 1, 20, 100-page
PDF or Windows WinRT PDF save-reopen-render acceptance occurred in this
development environment. RELEASE NO-GO. No PRIVATE/main/merge/force/root
LICENSE, signing key, private asset or customer data touches.

Official sources: https://github.com/jspecify/jspecify/releases/tag/v1.0.0
https://jspecify.dev/docs/using/
https://central.sonatype.com/artifact/org.jspecify/jspecify/1.0.0 .
