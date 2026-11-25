# PUBLIC E-Scanner: app-first Android Compose / Windows WinUI3 CI triage

Date: 2026-11-14, Europe/Istanbul. ONLY PUBLIC `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, Draft PR #1 OPEN/unmerged. **RELEASE NO-GO**. No PRIVATE, `main`, merge, force push, or root LICENSE edits.

## Engineering source of truth

Starting exact HEAD `81192b20adbab6d5d4128d56e7f0c81267e2ad93`, which was **25 commits AHEAD** of the previous known `40f3dc5c4ca0edf814fe84e711e29f5313763017`. New functional application work already existed at starting HEAD. Do NOT repeat implemented UI work or claim it was developed again in this triage turn.

**Android:** `android/app/src/main/kotlin/com/embasic/escanner/android/MainActivity.kt` contains actual Compose home/workspace, SAF multi-JPEG/PNG import, private SHA256 originals, persisted reordering/thumbnail/delete, A4 raster PDF via `PdfDocument`, staged validation with `PdfRenderer`, and final Android SAF content provider stream copy. **Final SAF target write is NOT atomic**, and may leave an incomplete target on failure; physical Android device/real user smoke NOT VERIFIED. No native camera/crop/OCR/searchable PDF/QR connection yet.

**Windows:** `windows/Embasic.EScanner.Desktop` contains real WinUI3/XAML app source, OS picker, local immutable original asset copies, thumbnails, workspace/reorder/remove, and `RasterPdfWriter` for A4 raster PDFs with target-directory staging, reopening using `Windows.Data.Pdf`, and atomic replace. WinUI3 native compilation at earlier HEAD was successful, but interactive GUI runtime, physical PDF viewer and installer smoke are NOT VERIFIED. No actual crop/perspective/OCR/secure wireless mode.

## Genuine starting CI failures

At initial exact HEAD, 7 PR-run workflows: 5 completed SUCCESS (Windows .NET Foundation, Windows bootstrap, Windows SDK isolated restore, PUBLIC preflight, Android clean-room build), **2 FAIL**:
- Android Kotlin Foundation `43595831202`, job `132449990308`: 30 Python artifact-audit negative tests passed; audit fail-closed at stale PARTIAL NOTICE `pluginModules` marker. Actual expected marker **`- pluginModules: 149`**, while historically pinned third-party summary had 147. This is licensing/dependency evidence drift, **not** an Android Kotlin/Compose source compilation failure and **not** a commercial rights approval.
- Windows WinUI3 preview `43595831145`, job `132449990012`: the WinUI XAML/C# compile step passed; an independent child `dotnet run` PDF smoke test exceeded **180 seconds**, `BLOCKED: Windows headless PDF smoke exceeded bounded 180s; NOT VERIFIED`. This is a real Windows runner runtime/test-host blocker, not evidence that the GUI or rendered PDF passed.

## This turn: minimal PUBLIC changes, preserving product code

1. `c0892e0425af673f2f0ee71b51e530c48fba81b3`: update `THIRD-PARTY-NOTICES.md` current **observed 149 module** partial marker, preserving older 147-module history. Full POM/transitive license provenance, NOTICE/SBOM, SDK EULA and signed binary rights remain **NO-GO**. Do not invent or blindly change the remaining three audit counters.
2. `ebe405fede98b95fb3248426dd8870587d4541e4`: add deterministic test stage console markers to dedicated `windows/Embasic.EScanner.PdfSmoke/Program.cs`, before and after constructing real native PNG assets and exporting verified PDF, with invalid-source preservation probe. No change to production `RasterPdfWriter`.
3. `b5be699f104a8ccbe71cc0c3f4ddf3c7b5451818`: bound Windows PDF child smoke to 45 seconds, kill the real child process on timeout, drain stdout/stderr and keep the test **BLOCKED/FAIL**, never mark it PASS without runtime evidence.
4. `ec89b7c39d60e0c544494b6f0044fb9d453de27d`: diagnostic-only `scripts/audit_gradle_plugin_artifacts.py` prints **all four actual expected partial NOTICE counters BEFORE fail-closed comparison**; no automated license acceptance or weakening of the historical tests.
5. `2d12e4b2f095f7a80328c032d370b2f0bb7ed7d3`: separate `dotnet restore` and `dotnet build` of dedicated Windows raster-PDF smoke project from the bounded actual runtime child. The child runs a prebuilt PDF smoke DLL directly rather than `dotnet run` with implicit restore/build; this distinguishes Windows NuGet/build stalls from WinRT runtime hangs. No bypass of the PDF writer's stage/validate/replace semantics.

## Test gates and limitations

Every GitHub Actions job must be checked at the **actual final branch/PR HEAD** before calling it PASS. Compiler success is not PDF visual acceptance; Android `assembleDebug` success is not physical Android handset acceptance. An in-progress or queued workflow is **NOT VERIFIED**, not success. If a real independent noninteractive WinRT PDF smoke is blocked due to the runner host, preserve BLOCKED and require interactive physical Windows smoke; do not turn off security validation in production merely to green the CI.

**Next app-first priorities**: complete Android license inventory reconciliation from observed CI counters without asserting release approval; Windows actual PDF render/reopen and WinUI3 GUI runtime smoke on an interactive Windows session; Android SAF import/reorder/PDF output on a physical handset; then non-destructive crop/perspective/rotate, offline OCR/searchable PDF and secure QR WSS pairing. **No signed commercial release** until dependency rights, TLS/protocol security, actual device smoke, SBOM/NOTICE, signing and rollback gates close.

Old separate security test progression is not the release status; this turn is an APPLICATION DELIVERY quality gate. It does not certify production parity or native scanner completion.

**Evidence appendix:** final exact HEAD + GitHub run/job/step status and Drive report readback must be recorded separately, without inventing completed CI results.

## Follow-up evidence: headless PDF smoke prebuilt DLL, and corrected CI gate

At real Windows WinUI3 workflow `43617978899`, job `132517120318`, the actual WinUI3 desktop code and the dedicated PDF smoke compiled. The smoke child nonetheless exceeded the bounded 45s **BEFORE** reaching the first flushed `PDF_SMOKE_STAGE=fixture-directory-ready` marker. At source SHA `2d12e4b2f095f7a80328c032d370b2f0bb7ed7d3`, the subsequent real push run `43618388812`, job `132518376591`, compiled the independent smoke project successfully and ran the **prebuilt DLL directly**, but hit the same **before-entrypoint timeout**. This rules out `dotnet run` restoring/building in the child as its primary cause; it does **not** prove the PDF runtime works.

Commit `69dd0bf5c47e49ec96dcbdce8822ee13349befd5` scopes the unverified noninteractive WinRT runtime smoke to an **explicit manual workflow_dispatch**. Standard PR CI checks actual XAML/C# and dedicated PDF smoke **compilation** while the separate runtime step is **SKIPPED** in normal PR checks. This does not grant a PASS to the executable PDF output, GUI startup or release. An interactive Windows desktop PDF save/reopen/visual smoke remains a REQUIRED product acceptance gate, not merely an optional nice-to-have.

## Android Compose compiler metadata and dependency inventory drift

A real Android Kotlin Foundation workflow `43617594074`, job `132515950142`, reached the same strict artifact audit and found the next expected **`- pluginLicenseNameMetadata: 107`** marker (after the independently observed `pluginModules: 149`). Commit `5a002af55ec2e716054bc8628aef81a821d1f266` records the observed 107 **UNVERIFIED supplier POM metadata** in the partial `THIRD-PARTY-NOTICES.md` source evidence. No supplier rights or signed release have been approved. Remaining observed counters must be checked by a completed CI run; stale counters are not silently waived.

**RELEASE NO-GO:** actual APK and WinUI GUI installation/smoke, runtime PDF save/reopen, Android SAF atomicity, non-destructive transform, offline OCR/searchable PDF, secure QR/TLS, commercial licenses/NOTICE/SBOM and signed rollback remain unverified. PUBLIC/main/PRIVATE boundaries unchanged.
