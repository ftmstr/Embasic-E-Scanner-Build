# PUBLIC E-Scanner — live token-claim FILE ID and pinned RootDirectory-relative admission

Date: 2026-11-12 (Türkiye). PUBLIC repository: `ftmstr/Embasic-E-Scanner-Build`; development branch `fix/pdf-fixture-selftest-20261018`, PR #1 OPEN/DRAFT, merge disabled. No PRIVATE, main, force push, rights-holder root LICENSE, third-party package, production credential or user document changes.

## Canonical baseline

Starting exact PUBLIC HEAD `c7f5070340473b262848ed61b8771a6ee66ad5c5`: six GitHub Actions workflows SUCCESS, 75/75 successful steps, Android JUnit 26 cases/0 failures/0 errors/0 skipped. Previous Google Drive Raporlar source: `1H7E6DTOvZikGeJlXMlGsbDo4DirD66xcqqIkET8Ew34` (ancestor ACL and directory-handle chain). No later PUBLIC HEAD existed at the outset.

## True test-first RED: byte-identical NTFS tombstone swap

Existing `DurableReceiveJournalV1` verifies an immutable `token.claim` tombstone's content against a fixed synthetic session/token hash, but it did NOT bind the live journal to the original NTFS file identity. An unrelated, separately launched same-SID `powershell.exe` can move the tombstone aside, create a *different* `token.claim` file with exactly identical bytes and delete the old name. No extra directory entries remain and the synthetic bytes continue matching, so the previous journal admitted the subsequent page despite a replaced tombstone.

TEST-ONLY commit `33b911dff139d1196d782899475fd1a298d1894c`, **actual Windows .NET run 43263076348, job 131339240990 FAILED**, and **Windows bootstrap run 43263076549, job 131339241877 FAILED**. Both decoded job logs say `FAIL: same-bytes hostile token.claim identity swap admitted a page`. This is a real test-only security failure on Windows runners; it must remain recorded even after final GREEN.

The same test explicitly checks (i) the independently launched OS process actually completed the file swap, (ii) the original bytes and resulting bytes are byte-for-byte identical, (iii) the directory has no leftover `.prior` file, and (iv) the live journal **must refuse** the next page. Failure to prepare the attack is NOT VERIFIED, never a PASS.

## Source fix and staged verification

- First fix, `97464a47224b1c2c3c9eaa4096a170e4e151b246`: cache a unique `FileId` (NTFS volume serial + 64-bit file index) when the live journal creates `token.claim`; on every relevant `StableRoot` check, refuse any file-ID change regardless of content equality; on unexpected identity/ACL failure in `Commit`, permanently poison the live journal so restoring a file does not revive it. Historic recovery remains read-only and does not issue transport authority. This is **live-instance** identity protection; an untrusted process may still race before capture, and an exact identity cannot be derived merely from bytes across a full restart.
- Follow-up source `4abfd3eab4a415e5162d28e1b0eddf21c04c4190`: native Windows `NtCreateFile` user-mode system API (OS-provided `ntdll.dll`, no NuGet package), `OBJECT_ATTRIBUTES.RootDirectory` set to the already pinned session root `SafeFileHandle`, fixed canonical basename `token.claim`, `FILE_OPEN`, `FILE_OPEN_REPARSE_POINT`, `FILE_NON_DIRECTORY_FILE`, `FILE_SYNCHRONOUS_IO_NONALERT`, `SYNCHRONIZE | FILE_READ_ATTRIBUTES`, with handle-based file-ID and hardlink/reparse rejection. Native-call failure is fail-closed; no fall back to path-derived identity.
- Root pin requests `FILE_LIST_DIRECTORY | FILE_TRAVERSE` so that a child can be resolved against the open root. No root-relative authority is constructed from untrusted user filenames; the child name is restricted to a conservative lowercase ASCII leaf alphabet and length.
- The existing runner full synthetic durable-receipt matrix, Android parity fixtures and previous Windows ancestor owner/DACL tests remain mandatory. Fresh exact final SHA CI must be checked after any further code/documentation commit.

**IMPORTANT SCOPE:** This change moves only the LIVE TOKEN TOMBSTONE FILE-ID admission check to an already pinned RootDirectory-relative native open. It does **not** convert stage/blob/receipt creation, reads, `File.Move` or directory enumeration to handle-relative operations. It is not a guarantee against a malicious same-SID actor changing bytes in-place, swapping and restoring file IDs between checks, malicious privileged writers, hardlink/junction races, or an offline full-restart attacker. Full Windows HANDLE-relative child IO, robust same-SID hostile-writer race instrumentation, native Windows/Android device QA remain NOT VERIFIED.

Official Windows user-mode API contract: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile . Native API lifetime and all target Windows deployment environments require device/package smoke before commercial use.

## Not run / blocked / no-go

True physical ENOSPC, disk quota exhaustion, crash of the journal owner while writing its own stage/receipt, `fsync` interruption, OS/power failure, full directory metadata durability, 500/1000-page synthetic perf and full-resolution device profiling were **NOT RUN / NOT VERIFIED**, not fabricated as PASS. Earlier 20/100 perf measurements contain just 3 synthetic bytes per page.

Release remains **NO-GO**: CSPRNG/pinned TLS, Android native fd-relative provider, real image capture/processing, OCR and searchable PDF, Windows/Android feature parity, 42 Maven child-POM legal reviews, Windows SDK BuildTools EULA/REDIST, rights-holder root LICENSE approval, complete NOTICE/LICENSES/SBOM, signing, rollback and real-device smoke.

Independent progress gate counts remain: Android native 0/21 (0%), Windows native 0/20 (0%), parity 0/41 (0%), platform foundation 3/6 (50%), PUBLIC structural 4/5 (80%), signed release 0/8 (0%). No invented overall product completion percentage.

**Next critical scoped step**: full NTFS handle-relative create/read/stage and atomic rename, independently synchronized same-SID child-name swap/junction/hardlink tests and deterministic ENOSPC + actual journal owner process kill/restart. Android physical SecureDirectoryStream provider validation; keep PR Draft and release NO-GO.
