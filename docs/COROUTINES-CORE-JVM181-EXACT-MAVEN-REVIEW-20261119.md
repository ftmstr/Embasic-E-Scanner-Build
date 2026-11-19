# kotlinx-coroutines-core-jvm 1.8.1 — exact Maven and tagged LICENSE review (19 Nov 2026)

**Scope:** PUBLIC ftmstr/Embasic-E-Scanner-Build, Draft PR #1, branch fix/pdf-fixture-selftest-20261018. Initial SHA `b7844cc89ebe97e406ab96e98bf14c44c76f36d4`. No PRIVATE/main/merge/force/root LICENSE modifications. Only one of **88 missing Android Gradle resolved Maven NOTICE rows** is under examination. The separate **42 Gradle plugin child-POM license-review gaps** remain independent.

## Confirmed upstream provenance, before byte review

- Maven coordinate observed in the actual 19-Nov Android CI 44577539546 full Gradle graph: `pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm@1.8.1` with **found 0 NOTICE**; it is NOT preapproved.
- Official GitHub Kotlin/kotlinx.coroutines release ref `refs/tags/1.8.1` resolves to commit `cd696d3f8f4afdbc735915c2bded974616331b55`. Tagged `LICENSE.txt` full text is Apache License 2.0, Git blob `9c308d958bf91eafe83f66106ca692ff414a4965`. These tag/FILE references were inspected through the live GitHub connector; upstream publisher cryptographic signature is **NOT VERIFIED**.
- Official Maven Central coordinate (POM + JAR):
  https://repo.maven.apache.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.8.1/
- Exact official source LICENSE pinned to immutable upstream Git commit:
  https://raw.githubusercontent.com/Kotlin/kotlinx.coroutines/cd696d3f8f4afdbc735915c2bded974616331b55/LICENSE.txt
- Release description: https://github.com/Kotlin/kotlinx.coroutines/releases/tag/1.8.1

## Independent bounded evidence workflow

New `scripts/audit_coroutines_core_jvm181_source_review.py` first parses exact Gradle `debugRuntimeClasspath` and `debugUnitTestRuntimeClasspath` using the preexisting fail-closed `resolved_graph` function. It rejects version drift. A single exact Gradle cache JAR must be found, without symlink/bounds ambiguity.

Only 3 literal immutable HTTPS URLs are accepted: official Maven Central POM, official Maven Central JAR and immutable GitHub release-tag LICENSE.txt. Reject redirects, malformed XML, multi-license ambiguity, mismatched coordinates, oversized JAR/ZIP, duplicate or unsafe ZIP members, missing expected `Job.class` and `BuildersKt.class`. Compare exact Maven JAR SHA-256 + byte size against the actually resolved local Gradle JAR. Independently validate tagged LICENSE Git blob SHA-1 and Apache Version 2.0 header. Store official POM/JAR/LICENSE SHA-256 in bounded report.

The first remote source validation must retrieve **real** hashes. No Maven POM/JAR SHA is guessed. If the source/live verification succeeds, capture the hash evidence, pin the 3 exact values into the checker, include byte-identical upstream LICENSE in `third_party/kotlinx-coroutines-core-jvm-1.8.1/LICENSE.txt`, and only then add one source-backed partial NOTICE row. Do **not** mark any module approved in advance.

New synthetic offline regressions test correct shape, immutable tag pin, wrong coordinates, changed byte size, forged license name, malicious ZIP, symlinked/multiple cache JAR, missing Gradle selection, unavailable upstream, and continued releaseApproval=false. These synthetic tests are explicitly not source-byte proof.

The independent source-check step runs after the existing 88-row Android NOTICE fail-closed gate under `if: !cancelled()`, with separate 14-day evidence artifact. A successful source-specific audit never turns the overall Android Foundation CI green while NOTICE remains incomplete. `LICENSE/NOTICE/SBOM`, `APK packaged scope`, `publisher signature`, `source-rights retention` and release gates remain **NOT VERIFIED**.

## Physical QA and product state

Actual Android DocumentsProvider JPG/PNG and native 1/20/100 raster PDF **NOT RUN**; Windows WinRT PDF save/reopen/render **NOT VERIFIED/BLOCKED**. Android and Windows image/PDF/crop/rotation/staging code untouched. Windows App SDK REDIST/EULA, signed release packages, store privacy/consent, real device visual QA, offline OCR, searchable PDF, secure QR/TLS phone capture, rollback and full platform parity are not release-approved.

**RELEASE NO-GO.** Source audit does not waive the other **87** potential NOTICE entries or the **42** separate Gradle-POM legal gaps. Any count decrease requires the final exact-HEAD Android CI logs to demonstrate it. No imagined product-completion percentage.

## Real first PUBLIC Android Foundation upstream-source CI — 19 November 2026

At initial strict-source-audit commit `7c5c836354ecacb217ce44204c6511f51df7a4d3`,
the ACTUAL GitHub Actions Android Kotlin Foundation push run
[44605162262](https://github.com/ftmstr/Embasic-E-Scanner-Build/actions/runs/44605162262),
job `135846781951`, logged all of the following:

- New synthetic source-audit regressions: `Ran 14 tests`, `OK`.
- Independent live source-audit step **SUCCESS** after existing NOTICE
  gate correctly exited FAILURE at `total=88`; scoped GitHub artifact
  uploaded. Full Android workflow remained FAILURE.
- Maven Central exact POM **2,196 bytes**, SHA-256
  `47c6a50b14151e8faf7f350a95235c37d12abc38bfb055b668974293172daf2c`,
  direct supplier licence metadata: `The Apache Software License, Version 2.0`.
- Maven Central exact JAR **1,546,991 bytes**, SHA-256
  `f3d4f5de1c391bbcc20f3b3435ccbac013521e76b6902d7d59635ec15c1f797e`,
  equal in exact bytes to locally resolved Gradle-cache JAR.
- Kotlin/kotlinx.coroutines tagged upstream `1.8.1` full
  `LICENSE.txt` **11,398 bytes**, immutable Git blob
  `9c308d958bf91eafe83f66106ca692ff414a4965`, SHA-256
  `b1febe6399dffb10d19d35e7663ab16300c93cb0476a94115df1cc0097a8ffd8`.
- Maven JAR legal file inventory was empty:
  no `META-INF/*LICENSE*` or `*NOTICE*` records were present.
  Downstream attribution and packaging checks remain open.

These precise *observed* source SHA-256s are now pinned in the bounded
auditor; offline synthetic fixtures cannot replace them in CI. The verbatim
upstream tagged LICENSE is independently retained at
`third_party/kotlinx-coroutines-core-jvm-1.8.1/LICENSE.txt`, with Git
blob equality to original source, and verified by CI `sha256sum --check`.
One exact Maven purl row is included in the **PARTIAL**
`THIRD-PARTY-NOTICES.md`; all other unseen licenses remain fail-closed.

This is **one** package-level source identity and supplier license metadata
check; no cryptographic publisher-signature, APK/AAB inclusion, complete
transitive rights, statutory notices, SBOM, Windows REDIST/EULA, signing or
production license is approved. The separate 42 Gradle child-POM legal
reviews persist.

The reduction from NOTICE missing `total=88` to `total=87` is an
anticipated effect, **not a verified fact until new final commit HEAD CI**.
Source-signature and redistribution gates remain NOT_VERIFIED and release
NO-GO. Do not count an Android Maven network resolution failure as a source
compile bug.
