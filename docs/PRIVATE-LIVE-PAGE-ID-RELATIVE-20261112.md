# PUBLIC: immutable confirmed-page file-ID admission (Windows)

Date: 2026-11-12, Türkiye. PUBLIC repository `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, PR #1 OPEN/DRAFT. **Release NO-GO**. No PRIVATE, main, merge, force-push, root LICENSE or external runtime dependency was changed.

## Exact starting evidence

At initial check, the branch matched `e0e069d91130a998c900268b5f87ac844e4b83a4` (ahead=0/behind=0), PR #1 remained Draft/unmerged, six GitHub Actions workflows were COMPLETED/SUCCESS with **75/75** successful job steps, Android JUnit XML had **26/26** cases (0 failed/error/skipped), and the previous 12-Nov report `1nQ4zhU8JZOvf9lbQIjkr94RMQwAIB5PoQnDea7A1WyM` was read in Google Drive/Uygulama/Embasic E-Scanner/Raporlar. The PUBLIC README/architecture continue to specify Windows **C# .NET 10 / WinUI3**, Android **Kotlin/Compose** independently. They remain foundation scaffolding, NOT a finished scanner.

## Test-FIRST real RED — prior confirmed page identity substitution

The prior journal pinned the live token.claim file ID, but re-audited existing page blob and receipt **content only** on subsequent commits. Two live malicious scenarios use a real independent same-SID `powershell.exe` process to (a) move `page-0000.blob` or `page-0000.rec` aside, (b) create a *different NTFS inode* with **exactly identical bytes** at the same name, and (c) delete the moved file. The positive control verifies the process succeeded, source bytes were preserved and exactly three expected directory entries remain.

Test-only commit: `cfa330425cb21d6e122e3e76ae46591e42535dc8`.
- Windows .NET Foundation run **43282542569**, job **131407339616**: **FAIL**, log `FAIL: same-bytes hostile prior-page page-0000.blob file-ID substitution admitted another page`.
- Windows bootstrap run **43282542476**, job **131407338547**: **FAIL**, identical failure.
- This proves **the blob case** as a real RED. The test stops at the first failure, so this test-only run did **not** independently reach the receipt branch; do not claim a separate observed receipt RED.

## Source correction and scoped GREEN

Fix commit `71356c781ce77e26e2822303d9d137880e5eb68d`, file `windows/Embasic.EScanner.Contracts/DurableReceiveJournalV1.cs`:
1. Each confirmed page in the live journal registers an exact pair of NTFS file IDs (volume serial + 64-bit file index) for `page-DDDD.blob` and `page-DDDD.rec` after a complete hash/receipt readback.
2. Both IDs are obtained using the already pinned private root `SafeFileHandle` and existing native `NtCreateFile` RootDirectory-relative checks, including reparse/hardlink rejection.
3. For later admissions, `StableRoot` compares all previously confirmed page IDs as well as the live `token.claim` ID, private root identity, parent ACL, ancestor handle liveness. A mismatch in `Commit` poisons the live journal and rejects further pages. No byte-identical swap is silently trusted.
4. In-progress page files are still written/read/renamed by existing path-based routines; the identity contract applies to *previously confirmed* live pages. It is **not** a full Windows HANDLE-relative I/O implementation.

**Physical GREEN on fix SHA**:
- Windows .NET Foundation run **43283087656**, job **131409249442**, **8/8** steps SUCCESS; log `PASS: live prior-page blob and receipt identity swaps rejected`.
- Windows bootstrap run **43283087479**, job **131409247203**, **13/13** steps SUCCESS; same real adversarial log. Both branches run in the final test.
- Existing token-claim same-bytes swap, ancestor hostile DACL, alias/hardlink and 37 actual-file/90 decision golden scenarios are kept in the same SelfTest. No altered cross-platform golden fixture.
- 20/100-page Windows synthetic probes use only **3-byte/page** and have no full-resolution performance SLA. 500/1000-page profiling was **NOT RUN**.

## Threat boundary (do not overclaim)

This is a deterministic **between-commits / live-instance NTFS file-ID substitution** defense. It is not a proof of protection from a same-SID attacker who swaps and restores between checks, writes the *same inode* in-place, overwrites current page before its ID is captured, manipulates directory ACLs with privileged rights, or attacks an offline, restarted process. Read-only `Inspect` still checks the content chain, does **not** possess a trusted pre-restart page-ID anchor and never grants transfer authority. Staging/blob/receipt CREATE/READ/RENAME are still path-based; handle-relative operations for all of them remain a release-blocking security engineering task.

**NOT RUN/NOT VERIFIED**: physical NTFS junction/symlink/hardlink continuously hostile writer TOCTOU; deterministic ENOSPC/low disk; actual journal owner process kill during its stage/receipt fsync; power cut, directory fsync, storage restart durability; Android device SecureDirectoryStream provider/UID behavior; 500/1000 synthetic pages; full-resolution real-device scans/OCR/PDF/transport/feature parity.

**BLOCKED / release NO-GO**: CSPRNG + pinned TLS/QR, 42 Maven child-POM legal reviews, Windows SDK BuildTools EULA/REDIST, root LICENSE rights-holder decision, complete THIRD-PARTY NOTICE/LICENSES/SBOM, native OCR/image/PDF and signed-package smoke/rollback. Android native 0/21, Windows native 0/20, parity 0/41, foundation 3/6, PUBLIC structural 4/5, release 0/8 are *independent* acceptance gates, not total project progress.

**Next single critical turn**: implement explicit Windows handle-relative stage/blob/receipt CREATE/READ/RENAME with atomic no-overwrite semantics and per-handle identity, synchronized same-SID adversarial child-name races, bounded deterministic ENOSPC fault injection and actual journal-owner process kill+restart. Android real-device NIO provider check is still pending. Keep PR #1 Draft and commercial release NO-GO.
