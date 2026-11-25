# Kotlinx serialization core JVM 1.7.3 — bounded Maven POM/JAR, tagged LICENSE+NOTICE and Gradle byte-parity review

**Date:** 20 Nov 2026 (Türkiye). **Scope:** PUBLIC `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, Draft PR #1. Starting exact HEAD `26011224b694bcd06f14862b184147fca2015094`. Exactly one of **86** missing Gradle-resolved Android Maven NOTICE entries: `pkg:maven/org.jetbrains.kotlinx/kotlinx-serialization-core-jvm@1.7.3`. Separate **42** Gradle plugin child-POM license metadata/legal reviews are not affected.

## Selected module and sources

The Android Kotlin Foundation CI run [44612437527](https://github.com/ftmstr/Embasic-E-Scanner-Build/actions/runs/44612437527) lists the PURL as `found 0` in exact resolved NOTICE graph. The Kotlinx serialization core library offers serial descriptors and serializer contracts; reviewing source provenance supports future strict raw-wire parsing without claiming it is implemented or validated on real devices.

The official `Kotlin/kotlinx.serialization` release `v1.7.3` resolves to **immutable GitHub commit** `d4d066d72a9f92f06c640be5a36a22f75d0d7659`. Independently through GitHub source:
- Top-level full `LICENSE.txt`, Git blob `9c8f3ea0871e0bfe81da0fa6e7c1d7d156dc380e`: Apache-2.0, 11,356 text bytes/characters (actual CI SHA-256 pending).
- Separate `license/NOTICE.txt`, Git blob `ee516ec09649791af5ff26c0346e748a881cacb7`, 497 text bytes/characters: Apache Section 4(d) notice. This is legally relevant; **do not drop it** just because the root license exists.
- Source `core/commonMain/src/kotlinx/serialization/KSerializer.kt`, Git blob `89107bba800bfd7d382255bb053a49efcf9f3b9e` with explicit Apache 2.0 header.
- Upstream `license/LICENSE.txt`, Git blob `f27c98811419cd02ffb74ed0c930a80ab7610e76` is a 601-byte source-file header, **not** a substitute for either the full `LICENSE.txt` or the distinct `NOTICE.txt`.

Pinned *literal* upstream endpoints for first real CI:
- Maven Central `https://repo.maven.apache.org/maven2/org/jetbrains/kotlinx/kotlinx-serialization-core-jvm/1.7.3/kotlinx-serialization-core-jvm-1.7.3.pom`.
- Maven Central `https://repo.maven.apache.org/maven2/org/jetbrains/kotlinx/kotlinx-serialization-core-jvm/1.7.3/kotlinx-serialization-core-jvm-1.7.3.jar`.
- Exact Git tag-root LICENSE `https://raw.githubusercontent.com/Kotlin/kotlinx.serialization/d4d066d72a9f92f06c640be5a36a22f75d0d7659/LICENSE.txt`.
- Exact Git tag-repository NOTICE `https://raw.githubusercontent.com/Kotlin/kotlinx.serialization/d4d066d72a9f92f06c640be5a36a22f75d0d7659/license/NOTICE.txt`.

## Fail-closed evidence discipline

New independent `scripts/audit_serialization_core_jvm173_source_review.py` parses actual Android `:app:debugRuntimeClasspath` and `:app:debugUnitTestRuntimeClasspath` via the existing bounded Gradle `resolved_graph`, rejects version drift/failed resolution, reads exactly one local Gradle cached JAR (reject ambiguous/symlinked/missing), obtains only the four literal official HTTPS source URLs (no redirects, size bounds), checks direct exact Maven POM coordinates and one Apache 2.0 supplier *metadata label*, validates no unsafe XML entities, checks JAR ZIP structure and expected `KSerializer.class`/`SerialDescriptor.class`, compares real Maven JAR versus Gradle cache by byte-size and SHA-256, confirms BOTH tagged source LICENSE and NOTICE immutable Git blob and expected content, writes structured scoped source evidence JSON. Failures exit nonzero; all unknown rights and full release status explicitly NOT_VERIFIED.

The **first** GitHub Actions run must discover actual POM/JAR/LICENSE/NOTICE SHA-256 values; no Maven binary SHA has been guessed. Only after genuine upstream and Gradle byte parity is verified may these actual SHA-256 values be made immutable audit pins, and the full tagged LICENSE and NOTICE source texts be retained verbatim as distinct `third_party` files with Git blob identity evidence. Only **one** exact source-backed row may be added to `THIRD-PARTY-NOTICES.md`; unknown Maven coordinates and the separate 42 child-POM gaps must remain fail-closed.

New synthetic offline regressions do not prove real publisher metadata, binary origins, commercial license or actual APK inclusion. The independent source audit runs even if the existing NOTICE gate fails, under `if: !cancelled()`, and retains a 14-day artifact. It **must not** bypass the original fail-closed NOTICE, cause an Android Foundation workflow SUCCESS or be labeled release approval. POM metadata plus immutable tag prove a limited source consistency claim, **not a publisher cryptographic signature, completed Apache Section 4 notices, transitive rights, SBOM or redistribution approval**.

## Product/runtime gates (unchanged)

Physical Android DocumentsProvider JPEG/PNG and real native 1/20/100-page PDF tests **NOT RUN**; real Windows WinRT PDF save/reopen/render **NOT VERIFIED**. Android Compose and Windows WinUI3 application image import, crop, EXIF, rotation, staging, PDF/export sources are **not changed** in this turn. The Windows .NET Foundation prior run 44612437533 initial attempt `Hostile rename timeout` failed, same SHA second attempt succeeded; preserve the first failure as unresolved flake assessment, never weaken that test. Complete offline OCR, searchable PDF, secure QR pairing over pinned TLS, app package smoke, release signing, THIRD-PARTY NOTICE/LICENSES/SBOM and Windows REDIST/EULA remain open. **RELEASE NO-GO**. No synthetic percentage of product completion.

## Actual first PUBLIC source CI — official SHA-256 results

At the first PUBLIC fast-forward source audit commit
`f870e419d9e23532c8f4d1718f1e26569901e135`,
Android Foundation **push** GitHub Actions run
[44626811889](https://github.com/ftmstr/Embasic-E-Scanner-Build/actions/runs/44626811889),
job `135922705707`, executed Android source/JUnit tests (74 cases, zero
failures/errors/skips), all **15 synthetic source-auditor regressions**,
and an independent live official Maven + tagged LICENSE/NOTICE review.
The live source verification step and scoped JSON upload **SUCCESS**;
the independent Android NOTICE audit deliberately still **FAILURE
total=86**. No NOTICE bypass was introduced.

Exactly recorded source bytes:
- Maven Central `kotlinx-serialization-core-jvm:1.7.3` POM
  **2,044 bytes**, SHA-256
  `734f5f749208dd0bef3d98caa594cf9222afdf0fee5b6843347a8fe64e240427`,
  direct producer license metadata
  `The Apache Software License, Version 2.0`.
- Maven Central JAR **390,987 bytes**, SHA-256
  `f0adde45864144475385cf4aa7e0b7feb27f61fcf9472665ed98cc971b06b1eb`,
  identical in SHA-256/length to the **actual locally Gradle-resolved JAR**.
  Mandatory `KSerializer.class` and `SerialDescriptor.class` members
  exist in the inspected bounded ZIP. No embedded LICENSE/NOTICE filename
  was observed, so downstream attribution/retention still requires review.
- Official `v1.7.3` `LICENSE.txt` **11,356 bytes**, Git blob
  `9c8f3ea0871e0bfe81da0fa6e7c1d7d156dc380e`,
  SHA-256 `c5accbbd8546e94c34aed24afe689a617627d18eed5a6c48277e48db57c23851`.
- Distinct official `v1.7.3` `license/NOTICE.txt`
  **497 bytes**, Git blob
  `ee516ec09649791af5ff26c0346e748a881cacb7`,
  SHA-256 `ec77bba5c852830abfdefcdefbf4a22577ff4df79ec323a898d5100ca1d6f8d6`.

The exact **four** official SHA-256s are now pinned into the source
auditor; content changes fail closed. Upstream legal bytes are published
verbatim with Git blob SHA identity to
`third_party/kotlinx-serialization-core-jvm-1.7.3/LICENSE.txt`
and `third_party/kotlinx-serialization-core-jvm-1.7.3/NOTICE.txt`;
GitHub Actions checks *both* SHA-256s before live auditor execution.
Only one precisely scoped partial NOTICE row and one matching
`NOTICE_LABELS` exact purl are added. All other unknown coordinates
remain fail-closed.

**Do not infer release approval:** Source hash pins verify official-source
content against a specific Gradle local cache, but do not independently
verify publisher signature, APK packaged component, full redistribution
conditions, transitive rights, complete notice retention or an SBOM.
Independent **42** Gradle child-POM reviews remain OPEN. The expected
reduction in unresolved Maven NOTICE entries from 86 to 85 must be
established by a **new exact final HEAD GitHub CI**, not by this
hypothesis. RELEASE **NO-GO**.
