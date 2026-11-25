# PUBLIC E-Scanner — pre-pin same-SID writer and 100/500/1000 NTFS handle resource RED/GREEN

Date: **2026-11-13, Europe/Istanbul**. Canonical PUBLIC repository `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, PR #1 **OPEN/DRAFT/unmerged**. **RELEASE NO-GO.** No PRIVATE, `main`, force-push, merge, root LICENSE, signing credentials, real user documents, or production deployment.

## Verified initial technical source

Initial exact branch HEAD `5b62bdacaf498b7a3e8eaec3853533e99c791439`, no later turn, Draft PR #1, six genuine GitHub Actions workflows **6/6 SUCCESS**, **75/75 steps SUCCESS**, Android JUnit XML **26 cases / 0 failure / 0 error / 0 skip**. The previous Google Drive report `11gIlsUD-7Mk2yg4hBOWsjYKlqpMBPNYJO2zxt4KcGDs` was read in `Uygulama/Embasic E-Scanner/Raporlar`.

PUBLIC README/architecture still target Windows **C#/.NET 10/WinUI 3** and Android **Kotlin/Compose/CameraX**. This repo is a security foundation, NOT a full scanner implementation or signed native release.

## Real same-SID writer that holds WRITE before immutable pin

Internal-only test barrier `BeforeLivePagePinsForTest` was added at source commit `699f84211a9a648e676d7fdb0ca57d4dd328594d`; it executes after full body/hash/receipt FILE ID readback, but **before** opening the live READ-share-only pins. Production composition does not assign this callback.

A genuine separate `powershell.exe` same-SID process opens either `page-0000.blob` or `page-0000.rec` using `FileMode.Open`, `FileAccess.Write`, `FileShare.ReadWrite`. The child remains alive holding the **same actual OS WRITE handle** while the journal tries to acquire its READ-share-only pin; readiness is established through a separate, checked marker, and the parent retains its PID. The expected admission is `Commit == false` with `LastNativeFailureStage` equal to `blob-pin` or `receipt-pin`, followed by permanent refusal to admit another page. After the rejection, the child writes `BAD` through the previously opened handle, calls `Flush(true)`, releases it and exits. Independent read-only `Inspect` must return `POISONED`; token replay must be denied. Distinguish real previously open handles from a test that only attempts a NEW open after a pin.

Test commit `c14d80ad0e3e7c99ba63837c41b19ab25779bd98`: Windows .NET Foundation run **43492311786**, job **132116383215**, **8/8 SUCCESS**, real log: `PASS: REAL pre-pin same-SID WRITE handle denied for blob and receipt; post-rejection corruption detected on read-only restart`.

**Crucially, the pre-pin test was GREEN on its FIRST execution** under the previous page pin security mechanism. There was **NO new pre-pin security RED**; do not claim the new test found a vulnerability or that production WRITE pins were introduced this turn. The negative branch already failed closed.

## True RED: real Windows access-token handle leak discovered by new workload

`windows/Embasic.EScanner.SelfTest/DurableReceiveJournalSelfTest.cs` now samples the Windows process's real `HandleCount` before, during and after page commits, then re-opens read-only recovery and checks that a consumed token cannot be reused. Opt-in `EMBASIC_ESCANNER_PERF_EXTENDED=1` uses **20, 100, 500 and 1000** pages. Each uses only **3 synthetic payload bytes per page**.

The first resource-test version `4991124bb3baa6abcafbd744097d462750555174` hit a **measurement-harness FAIL**, since `.NET Process.HandleCount` is cached until `Process.Refresh()`: baseline/live both read 644. This is not proof of a production token leak by itself. After test-only `Process.Refresh()` fix `0f185e90a22c5102341038d84428d2c0e9c4a47b`, real Windows .NET run **43493060799**, job **132118964499**, **FAILED** at `FAIL: live Windows NTFS pin handle budget 20 baseline=643 live=1224 expectedPins=40`.

Code investigation found `PrivateRootAcl` frequently called `WindowsIdentity.GetCurrent().User` **without disposing the returned disposable WindowsIdentity object**. This routine is invoked repeatedly through `GetRootId` and `StableRoot`, causing live Windows access-token HANDLEs beyond the legitimate two read-only file pins/page. That was an actual measured high-cardinality resource leak, unlike the earlier cached measurement issue.

Production correction `6f5fc9b46bbd654b2da28358d7044c4631548fc6` explicitly wraps the current identity in `using var currentIdentity = WindowsIdentity.GetCurrent()`, reads `currentIdentity.User`, and disposes the underlying token handle. No new license, dependency or weakening of strict NTFS ACL checks.

The Windows process-wide `HandleCount` can change slightly for unrelated runtime objects during a long test. The first 100-page test was *3 lower* than an exact 2-per-page delta; measurement correction `561f5bd2ad47b17bb48b875c902c50a19c3d666d` retains an explicit **2N-32 through 2N+128** acceptable live delta, checks `|afterDispose-before| <= 64`, verifies read-only `TOKEN_CONSUMED / N` recovery and replay denial. This is not a performance SLA or an assertion that process-global handle accounting is perfectly deterministic.

## Actual standard CI checkpoint, 20 and 100 pages

Windows .NET Foundation run **43493707674**, job **132121169049**, **8/8 SUCCESS**:
- 20: `baseline=289 live=336 afterDispose=289 expectedPinHandles=40 restartPages=20 replayDenied=true`, elapsed **940 ms**.
- 100: `baseline=290 live=487 afterDispose=280 expectedPinHandles=200 restartPages=100 replayDenied=true`, elapsed **7201 ms**.

## REAL opt-in 500 and 1000 Windows NTFS test: finished GREEN

An explicitly scoped PUBLIC `.github/workflows/windows-ntfs-handle-budget.yml` was added at source SHA `41ff02d0475442955e4ebc424732314e4ba63d47`. It operates only on PUBLIC branch, with **read-only GitHub token**, no secrets, synthetic files, `timeout-minutes: 45` and **no attempt to exhaust the runner system disk**. It runs `dotnet run` with `EMBASIC_ESCANNER_PERF_EXTENDED=1` on a real GitHub `windows-latest` runner.

**Push-triggered** GitHub Actions workflow **43493790641**, job **132121451162**, **8/8 steps SUCCESS**, real Windows log:
- 20 pages: `baseline=289 live=336 afterDispose=289 expectedPinHandles=40 restartPages=20 replayDenied=true`, elapsed **797 ms**.
- 100 pages: `baseline=290 live=487 afterDispose=280 expectedPinHandles=200 restartPages=100 replayDenied=true`, elapsed **10540 ms**.
- **500 pages**: `baseline=281 live=1284 afterDispose=280 expectedPinHandles=1000 restartPages=500 replayDenied=true`, elapsed **66787 ms**.
- **1000 pages**: `baseline=281 live=2271 afterDispose=264 expectedPinHandles=2000 restartPages=1000 replayDenied=true`, elapsed **190412 ms**.

These are real NTFS file handles observed at run time; each successful page has two live immutable READ pins. The code checks the same synthetic receipt ledger after session disposal and denies consumed-token replay. **Physical ENOSPC, 500/1000 actual scanned camera-resolution pages, OCR/PDF/export throughput, and any production latency target are NOT verified.**

## Not run / not verified, and release gates

**NOT RUN**: actual safely isolated quota-limited Windows NTFS physical ENOSPC test (no verified disposable volume/rollback controls); Windows system C: was not filled and global NTFS quota was not modified; OS shutdown/powercut, directory metadata flush durability, kernel syscall interruption, 500/1000 *real full-res scanner pages*, Android physical device UID/fd-provider, signed Windows/Android packages, device restart and rollback.

**NOT VERIFIED**: same-SID hostile writer which already holds a write handle remains unable to modify data *after* a rejected session; instead, the tested contract is FAIL-CLOSED ADMISSION + post-corruption POISONED recovery. Windows same-SID fully offline blob+receipt forgery, hostile privilege, all pre-pin TOCTOU and ReFS/SMB behavior are not solved. Prior Android `SecureDirectoryStream` feasibility used Linux-host JVM, **not an Android device**. Cross-platform scanner feature parity is not complete.

**RELEASE NO-GO / BLOCKED**: rights-holder root LICENSE, 42 Maven child-POM and transitive commercial license review, Windows SDK BuildTools EULA/REDIST, full SBOM/NOTICE/LICENSES, secure QR CSPRNG+certificate fingerprint pinned HTTPS/WSS, platform-native scanning/image enhancement/OCR/searchable PDF/workspace, signed packages, visual QA, smoke and rollback.

Separate unchanged denominators (not product overall completion): Android native **0/21=0%**, Windows native **0/20=0%**, Android/Windows parity **0/41=0%**, platform foundation **3/6=50%**, PUBLIC structural **4/5=80%**, signed release **0/8=0%**.

**Next security priority:** verified isolated NTFS quota/physical ENOSPC and crash/restart with rollback; benchmark Windows pin-handle budget with real full-res page bytes; device-level Android NIO fd provider/UID acceptance; pre-existing hostile write handles that span user-mode check boundaries. No PRIVATE/main/force/merge/root LICENSE modifications.

**Final HEAD note:** the opt-in 500/1000 workflow is a **push** run at the last source/workflow SHA `41ff02d0475442955e4ebc424732314e4ba63d47`. This documentation-only commit will advance HEAD; it does **not** change executable source. Six standard pull-request workflows must still pass on the final documentation HEAD. Record both HEADs and do not mislabel the earlier push run as a final-HEAD run.
