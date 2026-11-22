# Guava ListenableFuture 1.0 — official Maven Central JAR and pinned v27.0 source audit (22 Nov 2026)

**LEGAL AND RELEASE HARD NO-GO.** This is one scoped third-party component investigation. No Android resolved NOTICE row, Gradle parent/child POM review, Windows native acceptance, SBOM, or release gate is waived.

## Canonical start

- PUBLIC: `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, initial SHA `0a3482cfaaaace70dc0a72a8953e3a431e01701a`.
- Draft PR #1 remains OPEN/DRAFT/unmerged. Seven starting exact-HEAD PR workflows 6 SUCCESS / 1 FAILURE = 85.7%; Android Kotlin Foundation fails **as intended** for **85 missing NOTICE rows**, including `pkg:maven/com.google.guava/listenablefuture@1.0 (found 0)`. Independent **42 Gradle child POM legal reviews** remain OPEN.
- This component was **not** any previously researched Startup Runtime 1.1.1, Interpolator 1.0.0, JetBrains annotations 23.0.0, Kotlin stdlib 2.3.21, or Serialization Core JVM 1.7.3.

## Official Maven binary and subtle version conflict

- Selected coordinate: `com.google.guava:listenablefuture:1.0`, **JAR, not Android AAR**.
- Maven Central POM: https://repo.maven.apache.org/maven2/com/google/guava/listenablefuture/1.0/listenablefuture-1.0.pom
- Maven Central JAR: https://repo.maven.apache.org/maven2/com/google/guava/listenablefuture/1.0/listenablefuture-1.0.jar
- Upstream official Google Guava v27.0 source module `futures/listenablefuture1` describes `listenablefuture:1.0` as containing **`com.google.common.util.concurrent.ListenableFuture`**; `listenablefuture:9999.0-empty-to-avoid-conflict-with-guava` is a distinct, intentionally empty artifact. The version must not be silently substituted by dependency resolution, nor may the real 1.0 JAR be assumed empty.
- Probe accepts only actual successful Gradle runtime/test reports selecting exact 1.0, a unique `~/.gradle/caches/modules-2/files-2.1/com.google.guava/listenablefuture/1.0/<hash>/listenablefuture-1.0.jar`, and complete official Maven JAR byte SHA-256 and size equality. It inspects ZIP integrity and requires **exactly one Java class** at `com/google/common/util/concurrent/ListenableFuture.class`. Any unexpected class, 9999 placeholder, traversal, symlink, duplicate or broken CRC fails closed.

## Official tagged Guava source and legal limits

- Guava official GitHub tag `v27.0` immutable commit `a35bfd9ea855539354b783ee74839e384f7af98a` (root tree `1d09e7a851c586b4c5de7a97bf03fd690123b0af`).
- Pinned `futures/listenablefuture1` tree `2d264994055c7f26a8e85dbdc31f979a3ccb8445`, 8 entries, `truncated=false`, with `pom.xml` and `src/com/google/common/util/concurrent/ListenableFuture.java` (Git blob `33b56d6a1bcdd0cc32092eb42adc8253b221e911`).
- Root `COPYING`, Apache License 2.0 full text, Git blob `d645695673349e3947e8e5ae42332d0ac3164cd7`, 11,358 bytes.
- Immutable full source license: https://raw.githubusercontent.com/google/guava/a35bfd9ea855539354b783ee74839e384f7af98a/COPYING
- The complete pinned **module subtree** shows no NOTICE filename; the legal analysis must not infer that the complete Maven artifact and downstream distributions have no NOTICE/attribution duties. `v27.0` source has the historical module with version 1.0, but **exact source-to-Maven-JAR reproducibility, artifact signing, parent POM inheritance, publisher signature and legal closure remain NOT VERIFIED**.
- `scripts/audit_guava_listenablefuture100_source_review.py` fetches only fixed HTTPS Maven Central POM/JAR and immutable Guava COPYING/module tree URLs, with redirects blocked, size/ZIP/POM/GAV/Gradle limits and a short-lived GitHub token confined to the single pinned Git tree API GET. A POM license declared through a **parent** is explicitly **not accepted as directly verified**.
- `tests/test_guava_listenablefuture100_source_review.py` exercises deterministic synthetic POM, JAR/ZIP, exact-version-vs-empty, module tree, symlink/cache mismatch and fail-closed gates. Synthetic test results are **not** live supplier evidence.

## Outstanding evidence and physical acceptance

At initial commit official Maven POM/JAR SHA-256, local Gradle byte parity, exact JAR class/legal inventory, hosted CI and source artifact are **NOT VERIFIED**. After first real source CI passes, pin observed full Maven hashes, rerun all seven exact-final-HEAD PR workflows and record their independently verified results. Do not invent hashes, intermediate PASS claims, or percentages.

Android physical DocumentsProvider JPEG/PNG and native 1/20/100-page PDF: **NOT RUN**. Windows physical WinRT save/reopen/render: **NOT VERIFIED**. No changes to scan-domain imaging, PDF, crop/rotation, thumbnail/workspace, SDK, dependency versions or QR/TLS. Windows hostile rename historical timeout/follow-up success is retained unchanged. Android 85 NOTICE and separate 42 Gradle child POM remain OPEN; complete NOTICE/LICENSES, source/commercial obligations, signatures, SBOM, package smoke and platform parity are NOT VERIFIED. No PRIVATE/main merge/force/tag/release/installer. **RELEASE HARD NO-GO.**
