# kotlinx-coroutines-android 1.8.1 — official Maven JAR/POM and tagged LICENSE review (19 Nov 2026)

Scope: PUBLIC ftmstr/Embasic-E-Scanner-Build, Draft PR #1, branch fix/pdf-fixture-selftest-20261018. Starting exact commit `7d792023facc415d4c08ac07e90166ee16ffa65f`. One of the **87 missing** Android Gradle-resolved runtime/test NOTICE entries is under investigation. The **42** separate Gradle plugin child-POM legal gaps are a different gate and are not modified.

## Selected Maven module and upstream evidence

`pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-android@1.8.1` was listed as `found 0` in the real 19-Nov exact-HEAD Android Kotlin Foundation CI log (run [44606630258](https://github.com/ftmstr/Embasic-E-Scanner-Build/actions/runs/44606630258), job 135851932041). It is Android-specific coroutine main-dispatcher support, related to scheduling image/workspace work off the UI thread.

Official Kotlin/kotlinx.coroutines GitHub `refs/tags/1.8.1` resolves to immutable commit `cd696d3f8f4afdbc735915c2bded974616331b55`. Exact `LICENSE.txt` at that tag has Git blob SHA-1 `9c308d958bf91eafe83f66106ca692ff414a4965` and Apache License Version 2.0 text. Source code at tag `ui/kotlinx-coroutines-android/src/HandlerDispatcher.kt` contains package `kotlinx.coroutines.android`, sealed `HandlerDispatcher` and `AndroidDispatcherFactory`, Git blob `5ce3315db28683fc0f2941e51b1143ab9704f46c`. Neither a Git tag name nor a source license file is proof of signed publisher binary origin or full redistribution rights.

Pinned, literal official HTTPS sources (no arbitrary endpoint, redirect, or mirrors):
- Maven Central exact POM: https://repo.maven.apache.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-android/1.8.1/kotlinx-coroutines-android-1.8.1.pom
- Maven Central exact JAR: https://repo.maven.apache.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-android/1.8.1/kotlinx-coroutines-android-1.8.1.jar
- Exact tagged upstream LICENSE: https://raw.githubusercontent.com/Kotlin/kotlinx.coroutines/cd696d3f8f4afdbc735915c2bded974616331b55/LICENSE.txt
- GitHub release: https://github.com/Kotlin/kotlinx.coroutines/releases/tag/1.8.1

## Bounded proof required

The source audit `scripts/audit_coroutines_android181_source_review.py` parses real `debugRuntimeClasspath` and `debugUnitTestRuntimeClasspath` Gradle output via the existing strict `resolved_graph` logic. It fails if this coordinate isn't selected or a new version is resolved. It reads one exact Gradle hash-cache JAR (no symlink/multiple candidate, bounded byte size), fetches official Maven POM and JAR and immutable tagged LICENSE, validates POM coordinates and direct supplier license label, ZIP member bounds and expected Android-dispatcher classes, official JAR versus Gradle cached JAR SHA-256 + length, and tagged LICENSE Git blob plus Apache Version 2.0 text. It emits a scoped JSON with SHA-256 and release gates explicitly FALSE/NOT_VERIFIED.

The first run discovers genuine POM/JAR/LICENSE SHA values. **Do not invent them or add a NOTICE license label before live CI verifies them.** Offline tests use synthetic ZIP/XML and cannot substitute for official-source parity. In a subsequent reviewed change, pin actual source SHA-256, retain verbatim upstream LICENSE at a distinct `third_party` path, and add a single verified module-specific NOTICE row without weakening any of the other 86 missing entries.

The independent GitHub Actions step runs after the existing fail-closed NOTICE gate with `if: !cancelled()`. It is permitted to complete its source validation and upload a 14-day diagnostic artifact **even while the parent Android Foundation workflow correctly FAILS** due to missing other NOTICE rows. Network outages are `BLOCKED_SOURCE_NOT_VERIFIED`, not product code regressions. The independent 42 Gradle child-POM gaps remain open.

Physical Android DocumentsProvider JPEG/PNG and real 1/20/100-page native raster PDF tests: NOT RUN. Windows WinRT PDF native runtime/save/reopen/render: NOT VERIFIED. Android/Windows image/PDF/crop/rotation/staging implementation unchanged. Signing, REDIST, SDK terms, complete legal NOTICE/LICENSES/SBOM, APK package inspection, offline OCR, QR/TLS pairing, parity and physical release acceptance remain NOT VERIFIED or BLOCKED.

**RELEASE NO-GO**. Do not claim runtime license closure, binary origin, transitive or commercial redistribution rights, app completeness or a product progress percentage from successful proof-of-provenance tests.
