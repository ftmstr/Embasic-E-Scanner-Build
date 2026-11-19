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
