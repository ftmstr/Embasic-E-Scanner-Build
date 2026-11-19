# FastInfoset 1.2.16 — exact Apache-2.0, EDL, FIME BSD and EE4J EPL/GPL metadata provenance

**Date:** 10 Nov 2026. **Only PUBLIC** ftmstr/Embasic-E-Scanner-Build, fix/pdf-fixture-selftest-20261018, PR #1 OPEN/DRAFT. **Legal release NO-GO.** SOURCE and byte evidence are NOT human legal clearance, product LICENSE grant, signed package audit or complete transitive SBOM.

## Correct scope: Gradle build tools, not an application release

The PUBLIC Android Gradle root/app buildEnvironment selects
pkg:maven/com.sun.xml.fastinfoset/FastInfoset@1.2.16.
It is one of 42 direct-child Maven POM licence-metadata review gaps
(12 child POM not cached; 30 cached POM without a direct licence name).
The build-tool graph is not an APK/AAB or Windows MSIX file inventory.

Child FastInfoset 1.2.16 source POM's copyright header expressly says
Apache License, Version 2.0; the published child POM's direct
licenses node is absent. Immediate Maven parent
com.sun.xml.fastinfoset:fastinfoset-project:1.2.16 lists BOTH
"Apache License, Version 2.0" and "Eclipse Distribution License - v 1.0".
Actual cached parent POM SHA256:
90582425adc1f40b41362dafb95173931225acaa5e79620d5e6bd52f646292ba.

Organizational ancestor org.eclipse.ee4j:project:1.0.5
cached POM SHA256:
916b4794d8d8220a59a3fdf6a64dbe794aeb23395e888b81ae36a9b5a2c591a6.
This distant *organizational* POM lists EPL-2.0 and GPLv2 with
the GNU Classpath Exception. It is NOT evidence that EPL/GPL/Classpath
automatically governs this child JAR or its application integration.

## Exact immutable original upstream sources

Upstream repository: https://github.com/eclipse-ee4j/jaxb-fi
Annotated tag 1.2.16 Git tag object
d7f66b8461f13509f1f3d2763533bfa5a57570ad,
peeled exact commit df8b153272fd07a5e584c04a774afc8f4e67905c.
GitHub signature verification: verified=false, reason=unsigned,
so the historical Git revision is pinned, NOT publisher-cryptographically
authenticated.

Original version-tag source files and exact Git blob SHA1:
- Root LICENSE: b5c38428d3486cd7c4f8adb0f3824a39a9987372;
  **Apache License, Version 2.0** complete root text.
- Root NOTICE.md: 85121e7dd8aac65432eec604c6fe12cce454e79c;
  supplier EDL 1.0 and SPDX BSD-3-Clause labels, project-wide third-party
  listing, trademark/copyright and cryptography notices.
- FIME/LICENSE-FIME.md: c739f78bc05856bfbfe35a5b76f2d4e6242cea66;
  a separate 3-clause-BSD-style supplier file. Whether FIME classes,
  source or compiled data are included in this Maven JAR or a product
  release is NOT VERIFIED.
- code/fastinfoset/pom.xml:
  4270e413e455d4a34912bce7ce6c34bab6636384,
  child version, Apache source-file header, parent coordinate.
- code/pom.xml: ea6296b6dbee1ccb3ae54900399d57cdda24bacf,
  Apache source header, 2 parent supplier names and build copy
  resources META-INF/LICENSE and META-INF/NOTICE.md.

The Apache root LICENSE, EDL project NOTICE, FIME BSD licence and
the parent metadata are DIFFERENT sources, not interchangeable licences.
Source-file copyright, modified files, actual class inclusion,
copyright/NOTICE reproduction and upstream exceptions need separate
human/technical review. Project-wide dependency names in NOTICE
do not prove they ship in the standalone JAR or E-Scanner products.

## Pinned Maven sources and bounded fail-closed verifier

- https://repo.maven.apache.org/maven2/com/sun/xml/fastinfoset/FastInfoset/1.2.16/FastInfoset-1.2.16.pom
- https://repo.maven.apache.org/maven2/com/sun/xml/fastinfoset/FastInfoset/1.2.16/FastInfoset-1.2.16.jar
- https://repo.maven.apache.org/maven2/com/sun/xml/fastinfoset/fastinfoset-project/1.2.16/fastinfoset-project-1.2.16.pom
- https://repo.maven.apache.org/maven2/org/eclipse/ee4j/project/1.0.5/project-1.0.5.pom
- Five more allowed raw sources at immutable original Git commit SHA above.

scripts/audit_fastinfoset1216_exact_license.py verifies:
1. Actually selected PUBLIC Gradle local child POM/JAR size/SHA256 and
   cached parent+EE4J ancestor SHA256 against Maven Central release bytes.
2. All 42 child legal metadata queue entries remain evidence-only with
   no forged license grant, inheritance flag or duplicate PURL.
3. Separate PARTIAL Android debug app/runtime/test dependency graph
   cannot silently select this FastInfoset coordinate without review.
4. Nine literal allowlisted HTTPS URLs, redirect refusal and bounded
   downloads; all five version-tag Git SHA1 source blob identities.
5. Exact Maven POM to immutable tagged parent/child source POM byte parity
   and required parent/ancestor name references, without legal election.
6. Bounded ZIP archive member count, total uncompressed size, no
   traversal/symlink/duplicate legal resource, and byte equality
   between published Maven JAR META-INF/LICENSE and upstream root
   Apache LICENSE, and JAR META-INF/NOTICE.md and upstream tagged NOTICE.
7. Separate FIME BSD supplier source blob without falsely asserting
   applicability to specific JAR classes or legal right to redistribute.

tests/test_fastinfoset1216_exact_license.py contains 38 synthetic
adversarial negative cases: wrong POM, fake approvals, missing or altered
NOTICE, unsafe ZIP, FIME Apache substitution and ancestor legal-name drift.
Output fastinfoset1216-exact-source-legal-evidence.json is scoped source
metadata, NOT a complete product dependency graph, original licence bundle,
SBOM, signed package or legal clearance. CI can report byte parity PASS
only after actual runner job/log confirmation.

## Separate legal and release blockers

All 42 selected direct child Maven POM review items remain OPEN.
EPL/GPLv2 Classpath/EDL metadata does not automatically apply to
FastInfoset, and no rights option is selected. Any actual applicable
file-level licences, attribution and binary reproduction must be
established before shipping. Microsoft.Windows.SDK.BuildTools
10.0.26100.4654 exact EULA/REDIST and per-file shipping rights still
NOT VERIFIED; root E-Scanner product LICENSE requires owner approval.
True APK/AAB/MSIX package contents, native device CameraX/WinUI GUI,
QR fingerprint-pinned session, OCR, searchable PDF and full SBOM
release tests remain NOT RUN / NOT VERIFIED.

Native parity 0/41, foundation 3/6, structure 4/5, release 0/8.
2027-12-31 is conditional planning, not a delivery commitment.
