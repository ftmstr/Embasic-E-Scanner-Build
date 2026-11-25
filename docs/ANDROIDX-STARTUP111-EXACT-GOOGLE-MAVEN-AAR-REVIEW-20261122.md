# AndroidX Startup Runtime 1.1.1 — independent Google Maven source review (22 Nov 2026)

Status: legal RELEASE HARD NO-GO. PUBLIC start HEAD 066b60f745210a23081280f305343c7c404003aa; Draft PR #1 OPEN/DRAFT. Seven preceding PR workflow conclusions 6 SUCCESS/1 FAILURE, Android Kotlin Foundation fail-closed on 85 missing NOTICE entries. Selected new unresolved component pkg:maven/androidx.startup/startup-runtime@1.1.1. The separate 42 Gradle child POM legal gaps remain OPEN.

Official Google POM https://dl.google.com/dl/android/maven2/androidx/startup/startup-runtime/1.1.1/startup-runtime-1.1.1.pom
Official Google AAR https://dl.google.com/dl/android/maven2/androidx/startup/startup-runtime/1.1.1/startup-runtime-1.1.1.aar

Upstream androidx/androidx mirror snapshot change commit b02fe45471656462d4975afbbd6ff4b3814f23b1 (root tree 99ce1589c9a86bad6df9507dc0becb7b782f1e14). Module tree df712df9c71872c5d70a462f2c20be29de662410 has 49 complete entries including api/current.txt, src/main/java/androidx/startup/AppInitializer.java and AndroidManifest.xml; no separate NOTICE filename in module subtree. This is a LATER historical snapshot, NOT a verified official 1.1.1 release-source tag. Source-to-published AAR reproducibility and complete NOTICE obligations are NOT VERIFIED.

Root upstream LICENSE.txt at snapshot has Git blob e454a52586f29b8ce8a6799163eac1f875e9ac01, 10175 bytes, Apache License Version 2.0. Equivalent exact licence text already retained at third_party/androidx-interpolator-source-snapshot/LICENSE.txt, SHA-256 809fa1ed21450f59827d1e9aec720bbc4b687434fa22283c6cb5dd82a47ab9c0 and checked in CI. Reuse avoids duplication without claiming version-specific legal completeness.

Bounded source audit: fixed official HTTPS endpoints, redirect refusal, size limits, exact POM coordinate and licence claim, valid AAR ZIP with AndroidManifest.xml and nested classes.jar/AppInitializer.class, unique actual Gradle cached AAR/selected resolved graph, full SHA byte parity, pinned upstream license Git blob and complete tree. Synthetic regression tests are not official byte evidence. Before the first real exact-HEAD source CI, POM/AAR SHA are NOT VERIFIED and deliberately NOT pinned. No prior Interpolator, JetBrains annotations, Kotlin stdlib or Serialization Core check is repeated as the target.

Physical Android DocumentsProvider JPEG/PNG and true 1/20/100-page PDF acceptance: NOT RUN. Physical Windows WinRT save/reopen/render: NOT VERIFIED. Existing Android/Windows application image, PDF, crop and rotation code not modified. 85 NOTICE rows, 42 POM, historical Windows hostile rename, REDIST, signatures, SBOM and parity remain unresolved. No PRIVATE/main, PR merge, force, tag, package or release. HARD RELEASE NO-GO.

## Real first Google Maven byte evidence (22 November 2026)

- Independent PUBLIC PR Android Kotlin Foundation run 45019614684, job 137199377698, exact initial audit HEAD 795bb24867350b50cc718f5e20d74d48a8d9ede0.
- New Startup Runtime official POM/AAR source probe SUCCESS and JSON receipt upload SUCCESS, with seven deterministic synthetic security tests PASS. Overall Android Foundation FAILURE intentionally remains because 85 NOTICE rows are absent.
- Real Google Maven startup-runtime-1.1.1.pom SHA-256: f4114b5c6859bb1bc3caf281cb6d6f25998fa7f7292c64ceaea74a93210e746b.
- Real Google Maven startup-runtime-1.1.1.aar SHA-256: e0a6329a371262fe4c450372b70fdaf33b769ef6917094723787cfce896b1dd3, length 19,371 bytes; full SHA-256 and size equality to actual Gradle-selected AAR PASS.
- Immutable AndroidX later snapshot LICENSE SHA-256: 809fa1ed21450f59827d1e9aec720bbc4b687434fa22283c6cb5dd82a47ab9c0; exact Git blob e454a52586f29b8ce8a6799163eac1f875e9ac01.
- No AAR-embedded LICENSE/NOTICE filenames in observed archive. This fact does NOT waive 1.1.1 legal attributions or prove source-to-release equivalence. Publisher signature, actual APK/AAB embedding, redistributability and complete NOTICE remain NOT VERIFIED.
- GitHub Actions source receipt: android-startup111-source-evidence, artifact ID 14752559251, 1,136 bytes, 14-day retention, not a release SBOM.
- Official observed Google POM/AAR SHA-256 are now pinned into the independent source auditor. The next exact-final-HEAD PR CI must confirm these pins and the existing 85 NOTICE fail-closed status before declaring final workflow success ratio. The 42 child-POM gaps and Windows hostile rename history remain untouched.
