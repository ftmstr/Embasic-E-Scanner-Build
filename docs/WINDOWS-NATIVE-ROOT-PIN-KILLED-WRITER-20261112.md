# PUBLIC E-Scanner Windows root handle pin / separate-process crash-orphan hardening

Date: 2026-11-12 (Türkiye). Scope: **PUBLIC** `ftmstr/Embasic-E-Scanner-Build`, `fix/pdf-fixture-selftest-20261018`, PR #1 OPEN / DRAFT. Baseline HEAD `6305636e57630293e18ee93662962f8c797de4c2`, 6/6 workflow success, 75/75 steps, Android JUnit 24/24. Starting Drive report: `1p0-y5W5Deq7XI1ic-CtVlps2v8_jViPKYSpcCoOosnY`. The baseline remains history, not proof for a later commit.

## Test-first true RED

A **separate PowerShell process** performed `[System.IO.Directory]::Move()` against a valid Windows private root while its journal was alive. The test also checks the same external process can rename the root **after release**, avoiding a false PASS when the adversary cannot run. The old journal only sampled a file ID and closed the handle.

- RED test-only SHA `e03756c76559f4f3d279ac444ec84336b7fd2210`.
- Real Windows bootstrap run `43200126386`, job `131121049980`: `FAIL: hostile subprocess renamed OPEN Windows private root`. This is a real security-boundary failure.
- Intermediate root-handle attempt (metadata-only `FILE_READ_ATTRIBUTES` with no `FILE_SHARE_DELETE`) failed again on Windows .NET run `43200523976` and bootstrap run `43200521999`. The failed result is not a PASS and must not be hidden.
- Microsoft CreateFile documentation specifies attribute-only access is unaffected by normal sharing restrictions; the revised native handle requests `FILE_LIST_DIRECTORY` (0x0001), not `FILE_READ_ATTRIBUTES` (0x0080), and share READ|WRITE without DELETE. Reference: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea

## Production behavior (scoped claim)

Windows `DurableReceiveJournalV1` now explicitly owns a `SafeFileHandle` for its live lifetime and implements `IDisposable`. `Open` validates existing root owner/DACL, lexical no-reparse chain and NTFS volume/file ID, then pins the *leaf* root using `CreateFileW`, `FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT`, `FILE_LIST_DIRECTORY`, `FILE_SHARE_READ|FILE_SHARE_WRITE`. Before accepting, the open handle's file ID and current path/ACL are checked against the originally authenticated root identity. Disposal closes the handle and terminates further mutable operations; read-only `Inspect` now disposes its inspection journal. Existing test-root lifetimes and the 24-instance replay-race test dispose all handles.

This is a **Windows root-renaming hold**, not full directory-relative IO: child file operations still resolve path strings, ancestor directories are not kept open, and an attacker with the same account's directory write permission may still race individual files or rename ancestors. Windows reparse/junction/hardlink continuous racing, ACL epoch changes, file replacement after recheck, NTFS hard reboot, network share behavior, and directory fsync are NOT VERIFIED. Physical Windows CI runner validation is limited to the fixture and specific OS environment.

## Killed external writer / restart shared contract

New **single-row, exact** common fixture `tests/golden/crash-orphan-v1.tsv` is consumed by Android JVM and Windows .NET SelfTest (missing/duplicate shape fails). A separate OS process writes only synthetic `stage-0000.tmp` after a valid synthetic `token.claim` and then forcibly terminates itself (Linux `kill -9 $$`, Windows `Process.Kill`). Each platform must find read-only `POISONED` recovery, reject the next commit and consumed-token replay, and leave the interrupted stage visible for inspection. No production customer data or signing material is used.

This simulates **killed external writer with orphan stage**, not the actual scanner capture worker being killed, an active stage `fsync` interrupted by process termination, ENOSPC/low physical disk, OS crash, device power loss, or verified directory metadata persistence. Those remain NOT VERIFIED.

## Golden, existing test evidence, release gates

Existing `private-root-alias-v1.tsv` (ancestor symlink / external hardlink, 2 rows), `durable-receipt-v1.tsv` (37 cases / 90 decisions), wire and receive-gate fixtures are preserved. Earlier 20/100 page filesystem probes use only 3-byte `abc` payloads. 500/1000 page extended profile remains NOT RUN until a real recorded run. No third-party dependency, package, private source snapshot or product root LICENSE was introduced.

**RELEASE NO-GO:** CSPRNG/QR and pinned TLS, image decoding/full resolution, camera/UI/OCR/searchable PDF, native Android and Windows parity, actual device acceptance, 42 Maven child POM legal queue, Windows SDK BuildTools EULA/REDIST, rights-holder root LICENSE, complete NOTICE/LICENSES/SBOM, signing/rollback remain BLOCKED or NOT VERIFIED. Do not merge PR #1 or label FINAL.

Progress denominators remain: Android native 0/21=0%, Windows native 0/20=0%, parity 0/41=0%, foundation platform 3/6=50%, PUBLIC structural 4/5=80%, signed release 0/8=0%. These are discrete gates, not an overall product progress percentage.

## Next security work after exact-head CI verification

First verify true final same-HEAD Windows and Android run/job/steps/logs and the Android JUnit count, correcting any real FAIL. Next build safe ancestor handle/fd pinning and handle-relative file staging/rename with hostile same-user child-file writer races. Add deterministic ENOSPC fault injection, actual app-process termination during stage/fsync, restart and directory metadata flush tests. Reassess effective Windows ACL/owner/identity changes across multiple accounts and Android device provider support before claiming platform parity.
