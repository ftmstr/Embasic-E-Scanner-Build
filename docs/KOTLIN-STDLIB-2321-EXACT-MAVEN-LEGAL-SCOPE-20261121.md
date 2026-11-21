# Kotlin stdlib 2.3.21 — narrowly scoped exact-source investigation (21 Nov 2026)

**Status: SOURCE VERIFICATION IN CI; ALL LEGAL/RELEASE GATES OPEN.**

The resolved Android Gradle debug/runtime and JVM-test graphs include the exact coordinate
`pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.3.21`. This is distinct from the
already-reviewed kotlinx-serialization-core-jvm 1.7.3 coordinate; no scan,
crop, rotation, EXIF, staging, PDF or Windows application implementation has been changed.

Official source endpoints used by the strict probe:
- Maven Central POM: https://repo.maven.apache.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/2.3.21/kotlin-stdlib-2.3.21.pom
- Maven Central JAR: https://repo.maven.apache.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/2.3.21/kotlin-stdlib-2.3.21.jar
- Kotlin upstream tag v2.3.21 immutable commit: `fea1ad8c18995b80d1ca0e3917056104613d23db`
- Upstream LICENSE: https://raw.githubusercontent.com/JetBrains/kotlin/fea1ad8c18995b80d1ca0e3917056104613d23db/license/LICENSE.txt
- Upstream NOTICE: https://raw.githubusercontent.com/JetBrains/kotlin/fea1ad8c18995b80d1ca0e3917056104613d23db/license/NOTICE.txt

GitHub Git tree for that exact commit identifies `license/LICENSE.txt`
as blob `d645695673349e3947e8e5ae42332d0ac3164cd7`, 11,358 bytes,
and `license/NOTICE.txt` as blob `80dbbefa483f605b7e69a1458f9f66b277b61988`, 482 bytes.
These are upstream **source** file identities, not publisher-signed binary attestations.

**Important legal scoping caveat:** the source NOTICE expressly says it applies
"in this case for the Kotlin Compiler distribution". Its applicability to
`kotlin-stdlib-2.3.21.jar` is **NOT VERIFIED**, irrespective of Maven
POM Apache-2.0 label or byte equality with the Gradle cache. Do not copy the
compiler NOTICE into the application's runtime NOTICE as a presumed legal closure.

`scripts/audit_kotlin_stdlib_2321_source_review.py` bounds exact literal
Maven and immutable GitHub HTTPS URLs, refuses redirects, rejects entity-bearing
POMs and contradictory module coordinates, checks Kotlin Unit class in a bounded
ZIP, compares complete official Maven JAR bytes with the one selected Gradle
cached JAR, and outputs distinct POM/JAR/LICENSE/NOTICE SHA-256 values. Its
JSON explicitly reports legal rights, publisher signature, APK packaging and
NOTICE applicability as unverified. The synthetic Python tests are *not* a
substitute for live upstream or Android physical checks.

**Do not remove** the 85 unresolved Android Maven NOTICE rows, the separate
42 selected Gradle plugin POM legal investigations, or the fail-closed
`THIRD-PARTY-NOTICES.md` audit on the strength of these source labels.
No root LICENSE, PRIVATE/main mutation, PR merge, release or signing permitted.

**Acceptance not yet observed at authoring:** real source GitHub Actions output,
verified immutable source SHA-256, fully completed seven exact-HEAD pull-request
workflows, physical Android DocumentsProvider JPEG/PNG 1/20/100 native PDF and
Windows WinRT save/reopen/render. All remain NOT VERIFIED/NOT RUN unless a later
exact-HEAD CI or independent physical evidence establishes otherwise.
