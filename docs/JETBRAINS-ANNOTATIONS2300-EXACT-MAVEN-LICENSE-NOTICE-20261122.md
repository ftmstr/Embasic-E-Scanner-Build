# JetBrains Annotations 23.0.0 — official Maven and tagged source review (22 November 2026)

**NOTICE / RELEASE STATUS: OPEN, no legal approval.**

## Source and scope
PUBLIC Draft PR #1, fix/pdf-fixture-selftest-20261018; 21-Nov starting HEAD 9ac90b8856f5b1e87357157983e0f7bfbb6074b6.
Actual Android Foundation PR workflow 44943468012, job 136965534378, listed unresolved pkg:maven/org.jetbrains/annotations@23.0.0 (found 0) among 85 missing NOTICE rows. This component is independent of previous Kotlin stdlib and kotlinx-serialization-core-jvm research and of 42 separate Gradle plugin child-POM legal gaps.

Official Maven Central POM: https://repo.maven.apache.org/maven2/org/jetbrains/annotations/23.0.0/annotations-23.0.0.pom
Official Maven Central JAR: https://repo.maven.apache.org/maven2/org/jetbrains/annotations/23.0.0/annotations-23.0.0.jar
Upstream release tag: https://github.com/JetBrains/java-annotations/releases/tag/23.0.0
Annotated Git tag object: 9a67a73e9da8de4321c97ba0cf9071839a5abf8e.
Peeled immutable source commit: 5d06c0c48e0a4fe44b2bc0d5d3e8b113c7a57de2.
Root LICENSE.txt blob: 4c4a741bfd6103cc173315b0c699ea93bfe71383, 11352 bytes.
LICENSE source: https://raw.githubusercontent.com/JetBrains/java-annotations/5d06c0c48e0a4fe44b2bc0d5d3e8b113c7a57de2/LICENSE.txt
The exact tag Git tree has truncated=false and 71 entries. Inspection revealed LICENSE.txt, but no NOTICE, NOTICE.txt or NOTICE.md. This is a limited repository-tree observation, not a release notice waiver. The tagged LICENSE text identifies Apache License 2.0. Cryptographic publisher/tag signature verification remains NOT VERIFIED.

## Exact component audit
The added scripts/audit_jetbrains_annotations2300_source_review.py obtains one specific official POM, JAR, tagged source LICENSE and tag tree. Inputs have strict HTTPS URL allowlists and size bounds; redirects, XML entities/doctypes, changed/ambiguous coordinates, unexpected legal labels, wrong tagged source blob, incomplete source tree, unexpected NOTICE and malformed/oversized JAR are rejected. The POM label remains a supplier claim only. Full JAR ZIP CRC and class signature are checked. Official Maven JAR is compared for complete size and SHA-256 equality against the unique actual Gradle-selected 23.0.0 cached JAR. Exact runtime/test dependency reports are required. SHA-256 values must be taken from an actual successful live GitHub workflow, never synthetic test mocks.

The new test file provides synthetic fail-closed unit regressions, not real official-source proof. The Android workflow source step runs with not-cancelled semantics even after the deliberate earlier resolved NOTICE gate failure, without weakening that gate. Evidence is separately uploaded for 14 days. The source audit cannot change Android/Windows app code, original image/PDF/crop/rotation behavior, dependency declarations or existing product NOTICE.

## Verification and release limitations
At this document creation time official Maven source SHA-256 values and Gradle parity require subsequent exact-HEAD GitHub CI readback and SHA pinning. Actual APK/AAB inclusion, app packaging, publisher signature, downstream notices, commercial redistribution, full transitive SBOM and complete licensed release remain NOT VERIFIED. The 85 missing Android NOTICE rows and separate 42 selected plugin child-POM legal investigations remain OPEN. The historical Windows hostile rename timeout and later success have not been reclassified.

Physical Android DocumentsProvider JPEG/PNG, native 1/20/100-page PDF: NOT RUN; physical Windows WinRT save/reopen/render: NOT VERIFIED. Draft PR #1 remains unmerged. No PRIVATE/main, force, root LICENSE, signing, release or installer operation is permitted. HARD RELEASE NO-GO.

NEXT: Complete exact-HEAD CI run and check the independent annotations step. Pin the actually observed official Maven hashes if successful, then obtain final seven PR workflow results and save/read back the Google Drive Raporlar technical report.
