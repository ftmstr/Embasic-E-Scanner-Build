# PR #1 — PUBLIC source, license and security review (29 October 2026)

**Review state: BLOCKED FOR MERGE / RELEASE NO-GO.** This is an evidence
inventory, not a declaration of legal title, security certification, or
permission to publish private sources. The only active repository is PUBLIC
ftmstr/Embasic-E-Scanner-Build; do not import PRIVATE Git history or assets.

## Scope examined

PR #1 GitHub changed-file inventory at the inspected HEAD:
- .github/workflows/windows-bootstrap.yml
- .github/workflows/public-preflight.yml
- README.md
- docs/BOOTSTRAP-STATUS.md
- scripts/public_preflight.py
- tests/test_public_preflight.py
- windows/Embasic.EScanner.Contracts/SyntheticPdf.cs
- windows/Embasic.EScanner.SelfTest/Program.cs

The examples and new preflight tests are synthetic. SyntheticPdf is a
closed-world fixture checker, not a general PDF parser or production PdfEngine.
Public CI uses contents: read and disables checkout credential persistence.
No signing key, production scan or private repository source was intentionally
introduced in this phase. A complete full-tree secret/provenance scan and
authorship attestation are NOT VERIFIED.

## Real test evidence

- Windows bootstrap and .NET Foundation on 17f6b0241a55fc269c2d2cef13675ee8b5d5dbcb:
  two independent runs with 5 contract, 3 baseline synthetic PDF, and
  16 malformed synthetic PDF checks per job; PASS with run/job/step/logs.
- Public preflight at eadbf020bc734235f1d47d15ab82c8b30cf77dda:
  eight deterministic Python standard-library regressions PASS locally
  and on GitHub Actions run 40885610298, job 123488370051.
- CI execution of the *auditor* may PASS while the audit result is BLOCKED.
  It always sets releaseApproved=false; strict mode exits 2 when prerequisites
  are absent. Passing an audit regression cannot authorize product release.
- Wrapper checks assess URL and declared SHA-256, plus local JAR checksum
  consistency. They do NOT establish upstream binary authorship or license.

## Blocking findings

| Gate | Source finding | State |
|---|---|---|
| Product source license | Root LICENSE variants absent | BLOCKED — rights holder must approve |
| NOTICE and SBOM | NOTICE and THIRD-PARTY-NOTICES.md absent, transitive inventory missing | BLOCKED |
| Android clean-room Gradle | settings.gradle.kts, build.gradle.kts, app build, gradlew absent at checked paths | BLOCKED |
| Android wrapper provenance | Wrapper JAR, properties, trusted hashes not found | BLOCKED |
| Source authorship / full-tree secrets | Inspected PUBLIC PR paths only | NOT VERIFIED |
| Android + WinUI native document features | Foundation bootstrap only | NOT VERIFIED |
| Immutable originals, offline OCR, atomic PDF, TLS pairing | PUBLIC native acceptance missing | NOT VERIFIED |

Inspected Windows .NET 10 Contracts/SelfTest csproj files specify only the
Microsoft.NET.Sdk and a project reference, with no external NuGet package
declarations. This does NOT establish a complete transitive dependency or
third-party licensing inventory.

## Acceptance criteria

1. Rights holder approves repository license, source origins, and an explicit
   allowlist for any separately sourced file or binary. Public visibility
   never implies an open-source license or commercial reuse rights.
2. Complete direct and transitive dependency/license review, SBOM, THIRD-PARTY
   NOTICE/LICENSES and explicit attribution/provenance.
3. Independently author/review Android Gradle project and approve wrapper and
   distribution binary origin with official SHA-256 fingerprints. Never import
   the PRIVATE binary or history automatically.
4. Preserve SyntheticPdf fail-closed regression checks without claiming they
   validate arbitrary PDFs.
5. Rerun Windows CI, Android JUnit/lint/assemble and native device smoke.
   Keep run/job/step/logs and hashes; do not treat unstarted jobs as test FAIL.
6. Independently verify security, immutable assets, offline OCR, atomic
   staged-validated PDF export, release signing and rollback.

**Decision:** PR #1 OPEN; do not merge automatically. main unchanged. Product
release NO-GO. Next task: resolve licensing and Android clean-room provenance
without weakening security checks.

## 29 October clean-room Android evidence update (supersedes earlier missing-source rows)

The Gradle project source files, Kotlin Activity/manifest, JDK17 options
and SHA-256-pinned 8.14.6 distribution metadata were created independently
in PUBLIC after the earlier table was written. No PRIVATE contents or
wrapper binary were imported. A separate GitHub Actions workflow verifies
the **official distribution ZIP hash before executing it**. On earlier
PUBLIC HEAD c65caa945aee1e1335391bf4d752faac4c12ec99, run
40922555249 (job 123619400407) reported official ZIP SHA-256 OK and
unsigned `:app:assembleDebug :app:lintDebug` BUILD SUCCESSFUL. This is
foundational compilation only, not Compose, CameraX, OCR, PDF or device
verification. Runner SDK 36 was present, but SDK Terms acceptance for release
is not verified.

The original Android wrapper-required workflow remains BLOCKED because
no approved `android/gradle/wrapper/gradle-wrapper.jar` and `android/gradlew`
have been added. The official expected wrapper checksum is recorded
separately; the absent JAR is not treated as verified. CI policy regressions
at HEAD a03c27da1afcad5f5087a6ed40e0d130197429e8 ran 11/11 PASS
on run 40922911516; they now require exact official distribution and
JAR digests, not arbitrary self-consistent 64-hex strings. The preflight
finding remains BLOCKED (license, notice, wrapper presence and provenance).

The Android build is therefore **one validated foundation compile/lint
gate**, not verified end-user functionality. The earlier statement that
Gradle source files were absent is historical and no longer current.
Root LICENSE, NOTICE/SBOM, complete dependency-transitive review, binary
provenance and product/device/release gates remain unresolved.
See android/README.md and docs/ANDROID-TOOLCHAIN-LICENSE-RESEARCH-20261029.md.
PR #1 must stay OPEN; no automated merge or RELEASE.
