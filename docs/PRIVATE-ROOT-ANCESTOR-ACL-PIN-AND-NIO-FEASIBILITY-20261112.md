# PUBLIC private-root ancestor ACL admission, handle chain and Linux JVM fd-relative feasibility

**Date:** 2026-11-12 (Türkiye). **Scope:** PUBLIC `ftmstr/Embasic-E-Scanner-Build`, `fix/pdf-fixture-selftest-20261018`, PR #1 OPEN/DRAFT; **RELEASE NO-GO**. No PRIVATE/main/merge/force/root LICENSE changes.

## Verified baseline

Starting exact HEAD `6dbfc0ead4562f904c92986fad237455e3e0d7b5`, 6/6 GitHub Actions SUCCESS, 75/75 successful job steps, 25/25 Android JUnit; 12-Nov Drive source report `12m4hlhbwt-LcMzmbvvIlS2qihO3QjtSaWBor0lpMub0`. Subsequent source SHAs require independent exact-HEAD checks; prior successes cannot be copied to them.

Current Windows C#/.NET 10 target is WinUI3 foundation, NOT Kotlin desktop; Android Kotlin/Compose is a separate full application. No real camera/OCR/searchable PDF native parity has been produced by this scoped security change.

## Baseline ancestor rename observation: GREEN, NOT RED

An independent `powershell.exe` process tried to rename the immediate parent of a live journal root while the journal pinned the leaf handle. The test also required rename success after `Dispose`; otherwise process absence or blocked access could produce false positives.

TEST-ONLY commit `e068baf8d016d8b5d874cdcb7a688ae0b66f9183`, Windows .NET Foundation run `43238917039`, job `131253682865`: `PASS: pinned Windows ancestor denies external rename until Dispose`. **This passed before new ancestor code.** It is a Windows runner observation, not proof for all parent/mount/reparse races. Do not call this a RED.

## Real security RED: foreign-writable parent DACL

The original `GetRootId` checked the session root owner/DACL and lexical reparse ancestors but did NOT check whether an immediate parent was foreign-writable. A process separate from the scanner uses `icacls.exe /grant *S-1-1-0:(W)` to grant Everyone WRITE to a parent; the child/root's DACL remains protected and owner-matched.

TEST-ONLY SHA `e52b18d894d9e7b874744f1737a364bd88cfb95f`, Windows bootstrap run **43239652927**, job **131256297601**, **FAILED** in physical synthetic PDF fixture. Decoded log: `FAIL: hostile ancestor NTFS DACL admitted secure child root`. This is a real independent process admission bypass under synthetic NTFS fixtures, not a speculative weakness. Historical failing runs are retained.

## Scoped repair: parent DACL + all lexical ancestor handles

`DurableReceiveJournalV1` now:
1. Requires the leaf owner to match the process SID and rejects all applicable untrusted mutating ALLOW ACEs and NULL DACL as before.
2. Separately checks immediate parent owner belongs to caller/SYSTEM/BUILTIN Administrators, and rejects applicable mutating ACEs for other SIDs. The parent isn't forced to share leaf ownership; OS-owned parents are allowed only under this narrow policy. Other ancestor ACLs are not globally proven safe.
3. Opens every lexical ancestor with native `CreateFileW` `FILE_LIST_DIRECTORY`, `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, `FILE_SHARE_READ | FILE_SHARE_WRITE` and **no `FILE_SHARE_DELETE`**, checks the opened handle is a non-reparse directory, then revalidates the leaf. Failure of any required handle is fail-closed, disposing already opened handles.
4. Keeps parent handles in `SafeFileHandle[]` throughout live journal lifetime; `Dispose` closes both leaf and ancestor handles deterministically. `StableRoot` rechecks handle liveness and `GetRootId`/immediate-parent ACL each time.
5. Tests both **fresh admission refusal** and **in-flight token claim refusal** after the separate process changes the ancestor DACL; a successful open earlier is not a permanent trust grant.

**Security boundary limitations:** Child token/stage/blob/receipt operations are still path-based, not Win32 `RootDirectory` HANDLE-relative. The parent chain is pinned but not a proof against a privileged/system attacker, a malicious same-SID writer racing file creation/rename, ACL changes between an individual check and use, NTFS junction/hardlink live race, or arbitrary file-system implementations. READ access for metadata-only handle does NOT deny rename: `FILE_LIST_DIRECTORY` is deliberately used. Ancestor owner/ACE effective-permission edge cases require separate trust-model review across actual Windows accounts, inherited deny/allow, ownership and privilege elevation.

## Android NIO fd-relative *feasibility probe only*

An added Android module **host JVM** JUnit test `linuxJvmSecureDirectoryStreamHandleRelativeFeasibility` checks the Linux JDK provider returns `java.nio.file.SecureDirectoryStream`; opens `actual.bin` by directory-relative `newByteChannel(..., READ | NOFOLLOW_LINKS)`, renames the open directory, creates a substituted directory at the original path and requires that the still-open secure stream reads original bytes. It also requires a symbolic-link child read with `NOFOLLOW_LINKS` to be rejected. The test uses synthetic ASCII bytes and no private data.

**NOT implementation:** the Android production `DurableReceiveJournalV1` still uses `Path` + ordinary NIO opens, not SecureDirectoryStream. Android's actual filesystems/providers may not expose `SecureDirectoryStream`, and API 26+ availability does not prove its secure provider implementation. On-device compatibility and explicit fail-closed adapter decision remain **NOT VERIFIED**. Linux renaming an open dir is permitted; unlike NTFS handle sharing, no rename lock is claimed.

## ENOSPC / process-kill / hardlink / release gates

Previous cross-platform `crash-orphan-v1.tsv` verifies a **separate synthetic external writer** is killed after partial stage, leaving `POISONED` recovery. It is not scanner-process crash during its own fsync. This turn did **not** emulate actual low-disk ENOSPC, physical power loss, directory fsync, storage quota, or JVM/Windows native app kill/restart during mutation. All are **NOT RUN/NOT VERIFIED**, not PASS. Old external hardlink and symlink tests remain separate, not live racing. Prior 20/100-page profiles use **3 bytes per page**, not full-resolution; 500/1000-page profiling is **NOT RUN**.

**NO-GO** persists for 42 Maven child-POM rights reviews; Windows SDK BuildTools license/REDIST; owner-approved root LICENSE; NOTICE/LICENSES/SBOM; CSPRNG and pinned TLS; real image, OCR, searchable PDF, Android/Windows native parity, signing, rollback and device acceptance. PR stays Draft, never merge.

Next critical action: validated HANDLE-relative child file IO with per-file handle identity, independent same-SID name swap/reparse/hardlink race tests; Android real-device provider assessment; bounded ENOSPC fault-injection seam and actual journal-owner process kill with restart/read-only recovery; only then performance 500/1000-page workloads. Update a dated Google Drive Raporlar report after *actual exact final HEAD* CI readback.
