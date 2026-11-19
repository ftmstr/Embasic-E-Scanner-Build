# PUBLIC E-Scanner — Windows RootDirectory-relative stage CREATE/READ/atomic no-overwrite RENAME

Date: 2026-11-12 (Türkiye). PUBLIC `ftmstr/Embasic-E-Scanner-Build` branch `fix/pdf-fixture-selftest-20261018`; PR #1 **OPEN/DRAFT**, release **NO-GO**. No PRIVATE, main, merge, force-push, root LICENSE changes or new third-party runtime dependency.

## Canonical starting evidence

Starting HEAD `5b32b268727d2886084ab32d8bf3035462bdb87e`, branch identical (ahead=0,behind=0), PR #1 Draft, 6/6 completed GitHub Actions SUCCESS, 75/75 steps SUCCESS; Android JUnit 26/26. Source Drive technical report `1DZpnM2cYgKJRmRFARJwmDQ_pNllhgRBcvTZ6UqSq2vU` was read from Embasic E-Scanner/Raporlar.

## Real test-FIRST RED — separately launched same-SID stage replacement

Test seam `AfterStageCreatedForAdversarialTest` is **internal and normally null**, accessible to the synthetic SelfTest friend assembly only, never wired from the production composition root. The scanner first writes a stage file; the test barrier synchronously launches real external PowerShell under the same Windows account *before* the original code samples the stage FILE ID. The attacker renames the stage, copies the same bytes to a new inode under the original name, removes the old inode and exits. The fixture confirms the attacker's actual success, byte equality and exact expected directory entries; setup failure is NOT VERIFIED, not PASS.

Test-only SHA `e31684351c34e5f5473a91e12ca17cfa2abf5977`:
- Windows .NET Foundation workflow **43285847992**, job **131418898415**, real FAIL: `FAIL: hostile same-bytes in-flight stage inode swap accepted a page`.
- Windows bootstrap workflow **43285847984**, job **131418900774**, same real FAIL.
Old code captured the already substituted file ID *after* stage creation, so content/hash checks and the path-based File.Move admitted the hostile inode.

## Native scoped fix

Code changes `b5229b3da338be2b2fe9ba99867ff0262aa2d32a`, `ee307b038d9b8cf7c5e4a1a382bbdecb45e97f2f`, root access `8bd57bd3f56e3ba6922f0920a9cc00a31ae58af7`, final native rename replacement `26acb532155a1b0aa0cc184b967bfc5b4f428b3a`:
1. All token, stage and receipt **FILE_CREATE** operations use `NtCreateFile` with a pinned private `SafeFileHandle` as `OBJECT_ATTRIBUTES.RootDirectory`, a generated single-leaf lowercase-ASCII basename, `FILE_CREATE` no-overwrite, `FILE_NON_DIRECTORY_FILE`, `FILE_OPEN_REPARSE_POINT` and write-through. The original stage NTFS FILE ID is recorded **while the creation handle remains open**, before the test barrier. An external rename/copy to a different inode immediately fails the identity comparison.
2. Bounded token/stage/blob/receipt reads and read-only recovery file reads use `NtCreateFile(FILE_OPEN)` by the same root handle; validate non-reparse and hardlink count=1, length, full bytes and file identity after handle read. No path-based FileStream fallback.
3. Rename opens the **source stage file by the pinned root handle** with DELETE access and requires the previously captured file ID. Its target is a canonical single-component `page-DDDD.blob` under the pinned root; replacement is explicitly disabled. Native `NtSetInformationFile` class **10 (FileRenameInformation)** is used with `ReplaceIfExists=FALSE`, root handle, UTF-16 length-delimited filename. A hostile existing target must remain unchanged and no receipt may be produced. There is no `File.Move`, absolute-path fallback or cross-volume copy.
4. The journal still pins original token/confirmed-page file IDs, rechecks owner/parent ACL, lexical ancestor handles, hash/receipt chain and new page order. Native/IO failures permanently poison live journal rather than authorize a restart.
5. Unused legacy absolute-path helper routines for claim/stage/receipt write/read/file-ID were removed. Only files/streams are now root-handle-relative; **directory enumeration and owner/ACL path verification are still path-based**, and native file operations still do not make all same-SID races safe.

## Test FIRST after implementation: failures must be retained

First native wiring commit `ee307b038d9b8cf7c5e4a1a382bbdecb45e97f2f` **failed** Windows .NET run 43286527823/job 131421272001 and Windows bootstrap 43286527899/job 131421272449 at the *positive* fixture `FAIL: success_page0 action COMMIT0`. Root `FILE_ADD_FILE` added in commit `8bd57bd3f56e3ba6922f0920a9cc00a31ae58af7` did not alone resolve the test (Windows .NET run 43286990547/job 131422892123 FAIL). Minimal internal non-secret error-stage instrumentation `ec0851a25708145e341b7d76a399aa1faae263e5` isolated `native-stage=stage-rename` on run 43287325814/job 131424071854. These are implementation FAILs, NOT runner/SDK queue errors.

Native class mismatch: Win32 `SetFileInformationByHandle` uses `FileRenameInfo=3`, whereas `NtSetInformationFile` uses `FileRenameInformation=10`; the latter is the RootDirectory-relative native rename tested. No insecure absolute-path fallback was introduced. Microsoft FILE_RENAME_INFO API reference: https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info . Native rename requirements: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information .

**Physical GREEN checkpoint**: at source SHA `26acb532155a1b0aa0cc184b967bfc5b4f428b3a`, Windows .NET Foundation run **43287979351**, job **131426334820**, **8/8 SUCCESS**, physical log `PASS: synchronized external stage inode swap rejected BEFORE page confirmation`; pre-existing token and confirmed page ID tests passed. 20/100-page synthetic Windows tests use only **3 bytes per page**, not actual scan performance.

## Additional test boundaries

A second independent same-SID PowerShell adversary creates a colliding `page-0000.blob` *after* the trusted stage is created. The native rename must refuse replacement and preserve the existing bytes, with no receipt. This is an actual no-overwrite fixture, not a new RED case against the old File.Move (which was also no-overwrite).

An additional **deterministic SYNTHETIC disk-full injection** throws `IOException` with Win32-style `ERROR_DISK_FULL` (HResult 0x80070070) after writing the first stage byte through the scanner's own native file handle. Required outcome: stage orphan (one byte), `POISONED` read-only recovery, no blob/receipt, token replay refused. This is NOT physical ENOSPC, a volume filled to capacity, forced OS writeback failure or sudden power loss. The test seam is internal and never wired in the shipping composition root.

Physical actual **journal-owner process termination during stage/fync**, directory flush, sudden power cut, arbitrary same-SID in-place rewrite, continuously hostile rapid name-swap/junction/hardlink race, offline trusted monotonic file-ID anchor, Windows native device/package, and Android physical device `SecureDirectoryStream` provider/UID QA remain **NOT RUN/NOT VERIFIED**. Existing external killed-writer orphan test does not prove journal-owner crash durability. 500/1000-page profiling remains **NOT RUN**, and 20/100 synthetic probes are only three-byte pages.

## Release and progress gates

**RELEASE NO-GO** remains for native OCR/image/camera/searchable PDF, secure QR/CSPRNG and TLS pin, platform feature parity, Android device adapter QA, 42 unresolved Maven child-POM rights reviews, Windows SDK BuildTools EULA/REDIST, rights-holder root LICENSE, THIRD-PARTY NOTICE/LICENSES/SBOM, signing/rollback/package smoke. Scope is PUBLIC security foundation only; no customer data or private code.

Independent acceptance counts, **not an invented overall completion percentage**: Android native **0/21 (0%)**, Windows native **0/20 (0%)**, Android/Windows feature parity **0/41 (0%)**, platform foundation **3/6 (50%)**, PUBLIC structural **4/5 (80%)**, signed release **0/8 (0%)**.

**Next scoped work**: physical synchronized same-SID child-name attacker running continuously; deterministic process kill/restart of the *journal owner* during native stage flush and post-rename, signed Windows package and NTFS/ReFS/SMB compatibility; Android device provider feasibility. Exact final HEAD and six GitHub Actions job/step evidence must be collected before any PASS or release claim.
