# PUBLIC E-Scanner — Real journal-owner process kill/restart at native stage and rename boundaries

Date: 2026-11-13 (Europe/Istanbul; GitHub Windows run logs in UTC on 2026-11-12). PUBLIC `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, PR #1 OPEN/DRAFT/unmerged. **RELEASE NO-GO**. No PRIVATE repository, `main`, merge, force-push, root `LICENSE`, production credentials or actual customer scans were touched.

## Starting source of truth

Exact initial PUBLIC HEAD `56be965e948fbcc504101cfb239f270815240e08` matched the branch and Draft PR #1; no later public turn was present. Six completed GitHub Actions workflows and **75/75** steps had conclusion SUCCESS, Android Gradle JUnit XML **26 tests, 0 failure, 0 error, 0 skipped**. Previous native RootDirectory CREATE/READ/RENAME report `13ndPrZBN119LpaLPFvLxJCr_WDk-wWwNPROb2KBmAsM` was read from Drive `Uygulama/Embasic E-Scanner/Raporlar`.

Canonical target stacks are **Windows C# .NET 10 / WinUI 3** and **Android Kotlin / Compose**; these remain PUBLIC foundation targets and **are not complete native scanner applications**.

## Real process topology and safety boundary

The existing Windows `Embasic.EScanner.SelfTest` executable now supports a dedicated `--journal-owner-crash-child` mode. The parent starts a **separate .NET OS process** via `dotnet` and the exact current SelfTest assembly, with the same account SID but its **own PID and actual DurableReceiveJournalV1 instance**. The child opens an ACL-hardened NTFS private root, claims a synthetic token, then commits one three-byte synthetic page through **the real native RootDirectory-relative journal code path**.

A TEST-ONLY internal callback halts this true owner process at one of two precise boundaries; the child writes and fsyncs an out-of-root *test control signal*, then blocks indefinitely while still owning its journal handles. The parent verifies that the child remains alive and its expected checkpoint marker is fully written, calls `Process.Kill(entireProcessTree:true)` on **that owning process**, waits for non-zero process exit and OS handle release, and *only then* inspects the on-disk journal using a **fresh independent read-only recovery instance**. On every case, reuse of the original synthetic token by a new journal instance MUST be rejected.

A separate normal-exit child-process positive control verifies the child binary can really complete a page and that the read-only inspection yields `TOKEN_CONSUMED / 1 page`; the normal control does not use a fake kill. All modes have explicit timeouts, positive process/marker controls, orphan shape assertions, and deterministic cleanup. A missing child or unavailable checkpoint is `NOT VERIFIED`, never a fabricated PASS.

Two killed-owner boundaries:
- **stage-prefix:** child has written a **single stage byte and performed `FileStream.Flush(flushToDisk:true)`** on the native stage handle, but has not written the rest of the stage and has not created a blob/receipt. Kill must leave exactly one-byte `stage-0000.tmp`, no blob or receipt, `Inspect=POISONED`, and token replay denied.
- **after-rename:** child has completed the existing native **no-overwrite handle-relative stage → blob rename**, but has NOT created the receipt. Kill must leave a complete three-byte `page-0000.blob`, no stage or receipt, `Inspect=POISONED` and token replay denied.

The test does **not** terminate in the middle of an uninterruptible NTFS kernel rename syscall, does **not** emulate a sudden power cut, and does **not** establish storage-controller persist barriers or directory metadata fsync/durability.

## Test first: failures and root cause

- Test harness new checkpoint `f61ec637d22f2860ec835dd5590c2e7fd4910f15`, child executable routing `51474c04c559c8cb174b2896f8ce9cb8aec782ae`, actual external-owner tests `662da48af3bafa866038a3fee162a7b1a994f387`.
- Initial test-only Windows .NET workflow **43306192792**, job **131490003886**, failed because the parent read the signal marker before the child closed a `FileShare.None` file: `IOException: file being used by another process`. This is a **test harness sharing race**, not a journal domain vulnerability.
- Signal-read retry fix `980b59364c2b90e564d18480adbeb68c75dae47c` corrected the fixture handshake without disabling file exclusivity.
- The next authentic **RED** Windows .NET run **43306546507**, job **131491237401**, and Windows bootstrap run **43306546693**, job **131491237947**, both FAIL with `FAIL: owner-kill stage-prefix failed durable orphan/poison/replay assertions stageBytes=0 blobBytes=-1`. This showed that the TEST-ONLY one-byte write was still held inside the managed `FileStream` buffer when the actual owner PID was killed, so the on-disk partial stage size was zero rather than the one-byte physical checkpoint required by the test.
- Fix `add25f598124676971b9873b0d8f195543e29071`: inside the **internal-only stage-prefix callback path**, flush the one-byte prefix with `Flush(flushToDisk:true)` *before* signaling the parent. This is a test checkpoint fix, not an unconditional extra flush in normal production path, and it is not a directory fsync/power-loss guarantee.

At source-fix SHA `add25f598124676971b9873b0d8f195543e29071`, real physical **GREEN**:
- Windows bootstrap run **43306820530**, job **131492177707**, **13/13 SUCCESS**. Real log `PASS: REAL journal-owner PID killed at stage-prefix; read-only restart POISONED and token replay denied`, and the same PASS for `after-rename`.
- Windows .NET Foundation run **43306820544**, job **131492178346**, **8/8 SUCCESS**, two identical physical owner-kill PASS entries.
- Existing adversarial same-SID stage-inode swaps, destination-collision/no-overwrite, prior blob/receipt ID, injected synthetic ERROR_DISK_FULL and independent **external** writer tests also stay GREEN in these runs.
- 20/100-page performance from these Windows runs still uses **only three synthetic bytes per page**; do not extrapolate to real full-resolution scans.

## What this verifies vs. what remains open

**PASS, scoped only to current Windows GitHub NTFS runner**: the journal **owner itself** can be forcibly terminated at two synchronized user-mode checkpoints, with on-disk orphan shape, read-only `POISONED` recovery and one-time token replay prevention genuinely rechecked after OS releases process handles. Distinguish this from the previous `killed_external_stage_writer` fixture.

**NOT RUN / NOT VERIFIED**: physical ENOSPC/low-disk/quota exhaustion, forced writeback failures, directory metadata fsync, sudden OS/power cut, killing *inside* an NtCreateFile/NtSetInformationFile kernel operation, continuous same-SID malicious in-place write or swap/restore races, ReFS/SMB, 500 or 1000 page load, signed Windows installation/rollback, Windows native UI/camera, and Android device fd-relative `SecureDirectoryStream` provider/UID. The earlier Android **Linux host JVM** SecureDirectoryStream feasibility test is not an Android device production adapter; its platform gate stays NOT VERIFIED.

**Release NO-GO**: 42 Maven child-POM license reviews, Windows SDK BuildTools REDIST/EULA, rights-holder root LICENSE, full THIRD-PARTY NOTICE/LICENSES/SBOM, secure pairing token CSPRNG and pinned TLS, real native camera/image/OCR/searchable PDF and Android-Windows feature parity, device smoke, signing and rollback remain unverified or blocked.

Independent unchanged acceptance gate counts: Android native **0/21=0%**, Windows native **0/20=0%**, platform parity **0/41=0%**, platform foundation **3/6=50%**, PUBLIC structural **4/5=80%**, signed release **0/8=0%**. These are **not** a product-wide percentage.

## Next one critical turn

Use a temporary safe Windows NTFS filesystem/quota scenario or isolated quota-enabled volume to test **physical** ENOSPC with actual journal-owner IO; instrument directory durability and crash recovery without treating GitHub runner limitations as app-code failure. Expand to continuously malicious same-SID child writer and test Android actual device provider/UID. Do NOT weaken fail-closed contracts, merge PR #1, access PRIVATE, change `main`/root LICENSE or declare RELEASE GO. Full final exact HEAD six CI workflow statuses and Google Drive report readback must be recorded for this turn after the documentation commit.
