# AndroidX Interpolator 1.0.0 — exact Google Maven AAR source and Gradle parity (22 November 2026)

**RELEASE / LEGAL APPROVAL: NO-GO. PUBLIC source verification only.**

## Distinct selected coordinate

The actual completed Android Kotlin Foundation run 45007344221 on PUBLIC exact HEAD 25438bc9df031b4c46281b25e327df29fe02ce68 reported `pkg:maven/androidx.interpolator/interpolator@1.0.0` among **85 missing resolved NOTICE rows** (found 0). It was not one of the already investigated JetBrains annotations, Kotlin stdlib or Serialization Core components. The 42 independent selected Gradle plugin child-POM legal gaps are neither reduced nor inherited/cleared. The source probe runs separately *after* the intentional NOTICE failure and cannot unblock that gate.

Official AndroidX release listing: https://developer.android.com/jetpack/androidx/releases/interpolator — stable 1.0.0, 21 September 2018; module is now in maintenance mode. It recommends Compose for new Android UI work. The resolved Gradle graph, rather than this listing alone, selects the exact component.

Official publisher artifact URLs:
- Google Maven POM: https://dl.google.com/dl/android/maven2/androidx/interpolator/interpolator/1.0.0/interpolator-1.0.0.pom
- Google Maven **AAR**: https://dl.google.com/dl/android/maven2/androidx/interpolator/interpolator/1.0.0/interpolator-1.0.0.aar
- This coordinate is an Android Archive artifact, not a standalone Java JAR. The bounded source probe independently inspects the nested `classes.jar` inside the AAR.

## Upstream source lineage and licence boundary

- Official AndroidX GitHub mirror https://github.com/androidx/androidx tracks AndroidX source, but Interpolator is **absent from the current branch** after a removal commit `4dd32c3eaf6cb9f062b560b00724f6f809ad38d3` (“Remove complete view based libraries”; no new 1.0.0 release implied).
- The removal commit's direct parent `15d3a78f3e1976f7dd6ba687cba586d79c9d16e5` still has module `interpolator/interpolator`.
- The parent's root source tree `e0c2ddf342c63d8fff763ca1c1d0059e086b47d1` contains full `LICENSE.txt`, Git blob `e454a52586f29b8ce8a6799163eac1f875e9ac01`, 10,175 bytes, carrying Apache License Version 2.0 text.
- Official pinned `LICENSE.txt` source: https://raw.githubusercontent.com/androidx/androidx/15d3a78f3e1976f7dd6ba687cba586d79c9d16e5/LICENSE.txt
- The pinned Interpolator module subtree `2eea69702006ce32a9832cc5f8f1b7fe7b7143c6` is complete (`truncated=false`), has 21 entries, `api/1.0.0.txt`, the Java Interpolator source, and **no separate NOTICE file** in that *specific module subtree*.
- **Critical caveat:** this is a later historical pre-deletion source snapshot; a byte-identical 2018 release-source tag, source-to-binary reproducible build, applicable complete NOTICE/attribution obligations, publisher signing and redistribution rights are **NOT VERIFIED**. A source tree without `NOTICE` cannot waive downstream legal obligations. Nor does a Maven POM Apache-2.0 label by itself grant blanket rights.

## Fail-closed bounded source gate

`scripts/audit_androidx_interpolator100_source_review.py` restricts inputs to the four exact Google Maven / immutable GitHub HTTPS URLs and refuses redirects, network status deviations, oversized input, unsafe/symlinked cache, changed Gradle-selected coordinate, invalid/ambiguous POM, XML external entities, malformed AAR, ZIP path traversal, symlink members, duplicate entries or corrupted ZIP CRC. It requires actual Gradle runtime/test successful dependency reports, a unique cached exact AAR, AndroidManifest.xml, nested classes.jar and an Interpolator class. It compares entire official AAR byte size and SHA-256 with the exact resolved Gradle cache AAR. It pins Git blob identity of the source licence and validates the complete module tree, recording upstream NOTICE absence only within that pre-deletion subtree. The GitHub Actions read token goes **only** to the fixed public GitHub tree API URL, not Google Maven or raw GitHub.

`tests/test_androidx_interpolator100_source_review.py` includes isolated, deterministic fake AAR/POM/Gradle/source-tree tests to defend against invalid inputs. Synthetic test PASS is never evidence of official publisher bytes. The source gate generates inspectable bounded JSON (including explicit BLOCKED status on fetch failure), uploaded separately for 14 days.

**At initial document creation:** official Google Maven POM/AAR SHA-256, actual Gradle byte parity, AAR embedded legal filename inventory and independent live CI are **NOT VERIFIED**, until the exact GitHub Actions result is inspected. The source auditor's initially empty hash pins must be populated **only after an actual successful live source match**, then rerun at the final exact HEAD. Do not invent SHA values.

## Release block and device acceptance

Unchanged: 85 Android resolved NOTICE gaps, 42 Gradle plugin child-POM issues, Windows hostile rename failure/success history, SDK REDIST/Terms, complete NOTICE/LICENSES/SBOM, publisher signing, real APK/AAB package content, Android/Windows feature parity, secure QR/TLS pairing and signed release.

Physical Android DocumentsProvider JPEG/PNG and genuine 1/20/100-page PDF: **NOT RUN**, no connected real target. Physical Windows WinRT save/reopen/render and PDF visual acceptance: **NOT VERIFIED**. App image, PDF, crop, rotation and workspace implementation is untouched. PUBLIC Draft PR #1 remains open, no main/PRIVATE/merge/tag/release/installer. **HARD RELEASE NO-GO.**
