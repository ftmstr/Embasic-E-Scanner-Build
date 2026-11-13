# PUBLIC Windows live-page READ pins — same-SID in-place overwrite RED/GREEN

Date: 2026-11-13 (Türkiye). Canonical PUBLIC repository: `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, Draft PR #1 OPEN/unmerged. **RELEASE NO-GO**. No changes to PRIVATE, `main`, merge state, root LICENSE, signed releases or production data.

## Initial canonical verification

Starting exact branch/PR HEAD: `2186ff45958c200a9bb81f81c3634f6f19c50416`, compare IDENTICAL (ahead=0, behind=0), 6/6 GitHub Actions workflows SUCCESS and **75/75** steps SUCCESS, Android JUnit **26 cases / 0 failures / 0 errors / 0 skips**. The 13-Nov Drive report `1fU1ng6t9W0VoEc8WdQm4LMR9ONTPxD-T1GNJUdp7UCI` was read from Drive `Uygulama/Embasic E-Scanner/Raporlar`. PUBLIC README and architecture approve Windows C#/.NET 10 + WinUI 3, Android Kotlin/Jetpack Compose independently; neither native scanner app is feature complete.

## Physical ENOSPC decision

A test which fills the GitHub Actions Windows runner's default system drive, or changes global NTFS quota policy for its host volume, is **not an isolated/safe physical ENOSPC fixture**. The runner/repository currently does not provide a proven dedicated quota-limited NTFS test volume and safe rollback controls. Therefore **physical ENOSPC, quota exhaustion, directory fsync, storage-controller writeback error and power cut are NOT RUN**. The prior deterministic synthetic `ERROR_DISK_FULL` injection and real journal-owner PID termination cannot substitute for physical power-loss evidence.

## Test FIRST: real adversarial RED

Windows SelfTest launches a real separate same-SID `powershell.exe` process which opens an already-confirmed `page-0000.blob` or `page-0000.rec` **in place** with WRITE access (FILE ID unchanged), writes a short different byte prefix and flushes. The real child runs **synchronously at the final live journal admission boundary**, after the existing readback/hash and NTFS file-ID validation but before `Commit` returns. This is an internal test-only hook; production composition never assigns it.

Test-only commits: `b656f4cc7db116de27706ff3a60a077bd46e8d7e` (synchronized final callback) and `9515cbc3f7305f7467af476dc5c928c995a42edb` (actual external writer and verified post-close positive control).
- Windows .NET Foundation run **43486705746**, job **132096962052**, **FAIL**: `FAIL: same-SID in-place page-0000.blob overwrite admitted at final live journal boundary commitReturned=True`.
- Windows bootstrap run **43486705872**, job **132096961986**, **FAIL**, identical result.
The RED stops at `blob`; `rec` does **not** have a separately executed historical RED in these test-only runs. This confirms that identity-only final admission could return success after current-page **content had changed**.

## Real Windows HANDLE-relative fix and live lifetime boundary

Production commit `da2dbf3e45e3fc79f705c1863c7947ad2f8de450`: on every confirmed successful page, after full hash/receipt readback and exact original NTFS FILE ID validation, open **two additional real SafeFileHandle read pins** for the current `blob` and `receipt` using the already pinned `RootDirectory` and native `NtCreateFile` with `FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE`, disposition `FILE_OPEN`, share **FILE_SHARE_READ only**. Source open validates the original FILE ID, rejects reparse and hardlink count>1. If either read pin cannot be obtained, `Commit` fails closed. Pairs are kept in `_livePagePins` for the duration of the session; `Dispose` closes both pins for every committed page before the root/ancestor handles. The regular bounded read and file-ID probe opens request compatible FILE_SHARE_READ (never SHARE_WRITE or SHARE_DELETE), allowing own read-only recovery and subsequent page commits without opening an attacker write window.

Windows sharing semantics deny **new** processes which request WRITE or DELETE on these files while their immutable READ pins remain open. The file-ID checks remain a separate defense against names being substituted. This does **not** revoke a conflicting writer handle obtained **before** pinning, block privileged kernel tampering or guarantee offline fidelity. Host-level same-SID access remains a threat boundary, not a secure principal separation.

Test correction commit `2cfaed1c6d3840c5fc8f05928d7d020959158c3d` keeps the shared cross-language `tests/golden/durable-receipt-v1.tsv` **unchanged** while modeling corruption tests *after the Windows owner explicitly disposes its live pins*: read-only recovery sees POISONED. For live previous-page replacement fixture, the independent same-SID process's rename must be denied; the benign following page must still commit. After `Dispose`, the real same-SID process can swap byte-identical content successfully, showing that an offline `Inspect` has no trusted pre-restart NTFS FILE ID anchor. These two different threat scenarios are not conflated. Android golden fixture **actions** use a different host implementation and cross-language lifecycle parity for the new Windows pinning adapter is **NOT VERIFIED**.

## Actual GREEN checkpoint

At source SHA `2cfaed1c6d3840c5fc8f05928d7d020959158c3d`, Windows .NET Foundation workflow **43487421113**, job **132099435936**, **8/8 steps SUCCESS**. Logs:
- `PASS: real same-SID in-place blob and receipt writes denied by LIVE journal pins`.
- `PASS: live prior-page blob and receipt identity swaps rejected`.
- 20 pages / 643ms and 100 pages / 4987ms, `syntheticBytesPerPage=3`, `noLatencySla=true`.

The final exact HEAD must be retested separately after this technical note commit and the final Google Drive report appended with final-HEAD real workflow IDs and Android JUnit results. An intermediate checkpoint is not final release evidence.

## Explicit NOT RUN / NOT VERIFIED / BLOCKED

**NOT RUN**: safe isolated physical NTFS disk-full/quota ENOSPC, actual journal-owner process kill *inside* a kernel/native syscall, directory metadata fsync and sudden power cut, 500/1000-page large-file/handle-budget performance, continuous uncontrolled same-SID high-frequency writers and swap/restore while a previously-open attacker handle remains live, real Android device SecureDirectoryStream/fd-provider and per-UID read/write rights, ReFS/SMB/OneDrive filesystem compatibility, signed native device package smoke and rollback.

**NOT VERIFIED**: holistic same-SID session isolation, integrity across offline attacks which can rewrite a blob **and** forge a matching receipt checksum, platform-native scan/OCR/PDF/transport, Android/Windows feature parity.

**BLOCKED / release NO-GO**: rights-holder root LICENSE, 42 Maven child-POM/transitive licensing reviews, Windows SDK BuildTools EULA/REDIST, complete THIRD-PARTY NOTICE/LICENSES/SBOM, secure QR one-time nonce CSPRNG, pinned HTTPS/WSS certificate fingerprint, signed APK/AAB and Windows installer, visual/native camera/OCR/searchable PDF, packaging and rollback.

Independent product gates remain **Android native 0/21=0%**, **Windows native 0/20=0%**, **platform parity 0/41=0%**, **platform foundation 3/6=50%**, **PUBLIC structural 4/5=80%**, **signed commercial release 0/8=0%**. They are not an invented overall product completion percentage.

**Next critical step:** a dedicated disposable quota-limited NTFS disk/volume with proven isolation, then actual ENOSPC/read-only restart, power-loss & directory metadata durability; Android hardware fd provider check. Separately test Windows file-handle budget at 500/1000 pages and pre-existing same-SID writer handles. PUBLIC PR #1 stays Draft, no merge or release approval.
