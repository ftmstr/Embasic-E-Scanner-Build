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

## Historical blocking findings (superseded by later dated updates)

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

## 29 October evening: wrapper/JUnit RED-GREEN evidence update

Source-only security fix, not release approval:

- PUBLIC wrapper import commit `c6a1521f200596e603ba505f581df73abf85ab89`:
  Gradle 8.14.6 JAR (44,309 bytes) independently hashed with SHA-256,
  equals official release digest
  `ad16bca46cb71bb5887c546860d93992aeee35c1fdaf4a242b0a612375d937e0`.
  Upstream immutable Gradle commit
  `c27417f274bd1cf2f36e1f93d54e3de840d54e43`,
  original `gradlew`, `gradlew.bat`, JAR and Gradle Apache-2.0
  upstream license retained as exact Git blobs, with 0755 Unix wrapper.
  Source tag `v8.14.6` itself contains an older bootstrap JAR. See
  `docs/GRADLE-WRAPPER-PROVENANCE-20261029.md`.
- Android wrapper CI now verifies JAR SHA-256 and pinned distribution hash
  **before** invoking the wrapper. Both independent wrapper-based and
  verified-ZIP Android foundation builds can be evaluated.
- RED CI on workflow commit `3f93400701a0520561b0349cc99a7f8b16731400`:
  job 123639082164, run 40928140967, assembled/linted successfully
  but `:app:testDebugUnitTest NO-SOURCE`; new XML gate intentionally
  failed with `BLOCKED: JUnit XML absent`. Prior build-only workflow
  success was not evidence of executed JUnit tests.
- GREEN CI on workflow commit `3d980decd9f9b5a49f3ef6fe5db5781c0afc01c4`:
  run 40928606110 job 123640715845 completed/success. Log includes
  `JUnit cases=6, failures=0, errors=0, skipped=0`,
  `BUILD SUCCESSFUL`, `lintDebug`, `assembleDebug`, and
  `PASS: 2 reviewed test-only modules isolated from debugRuntimeClasspath`.
  The six tests concern pure version/order/canonical SHA-256 contract
  boundaries; **not** camera/OCR/PDF/full feature parity.
- `junit:junit:4.13.2` EPL-1.0 is `testImplementation` only;
  transitive Hamcrest Core 1.3 is New BSD. The GREEN job verified both
  on JVM test classpath and absent from Android debug runtime. This is a
  documented test-only copyleft boundary, not rights approval to ship
  either dependency with an APK, nor full dependency-tree SBOM.
- `THIRD-PARTY-NOTICES.md` is now present but explicitly PARTIAL;
  upstream Gradle source license is preserved. The PUBLIC product ROOT
  LICENSE remains ABSENT and needs explicit rights-holder selection.
  Direct/transitive build plugin inventories, signing and device acceptance
  are still NOT VERIFIED. Do not mark PR #1 ready to merge automatically.

**Current blockers:** owner-approved source LICENSE, complete per-artifact
SBOM/LICENSES/NOTICE, WinUI3 and Android native user feature parity, security
and offline export, two-device smoke, signed package verification and rollback.
PR #1 stays open and release remains **NO-GO**.
