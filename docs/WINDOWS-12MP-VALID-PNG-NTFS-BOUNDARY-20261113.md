# PUBLIC E-Scanner — valid 12MP synthetic PNG, Windows NTFS receive and 32MiB fail-closed cap

Date: 2026-11-13 (Europe/Istanbul). Only PUBLIC `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, PR #1 OPEN/DRAFT/unmerged. **RELEASE NO-GO**. No PRIVATE/main/merge/force/root LICENSE changes or new runtime dependency.

## Canonical starting evidence

Branch and Draft PR #1 exact starting HEAD: `02d74cd3a9cf37b192cf946dee91ada97dc4dc37` (branch identical, ahead=0/behind=0); 6/6 completed GitHub Actions SUCCESS; 75/75 job steps SUCCESS; Android JUnit XML 26/26 with zero failures/errors/skips. Prior Drive report `1c4C9z3kmKXnEdsIwjoJabIz2D7AapUXMZA1xyjMPUQA` read and confirmed in `Uygulama/Embasic E-Scanner/Raporlar`. Existing 3-byte Windows NTFS **500/1000-page handle budget** run `43493790641`/job `132121451162`, 8/8 SUCCESS at source SHA `41ff02d0475442955e4ebc424732314e4ba63d47`. These are NOT camera full-resolution assets.

The PUBLIC Windows target is C#/.NET10/WinUI3; Android target is Kotlin/Compose/CameraX. Both are still incomplete independent scanner products and signed release is blocked.

## Safe physical ENOSPC decision

No verified isolated and safely disposable NTFS quota-limited volume with mount permissions and rollback was available on the GitHub Windows runner. Do NOT fill the runner C: disk or change global NTFS quotas. **Physical ENOSPC / writeback error / directory fsync / powercut NOT RUN.** Prior synthetic `ERROR_DISK_FULL` and real journal-owner process kill tests are not evidence of actual volume exhaustion or sudden power failure.

## High-resolution realistic-size, syntactically valid PNG test

A separate `--high-resolution-png-ntfs` SelfTest entrypoint and new Windows-only `HighResolutionPngJournalSelfTest.cs` create deterministic **synthetic** 8-bit RGB truecolor PNGs using PNG signature, IHDR, IDAT via `ZLibStream`, IEND, little-independent big-endian lengths, CRC32 and no scanline filter. An independent structural check verifies signature/dimensions/chunk CRCs, inflates IDAT, and checks full uncompressed scanline byte count. The actual ImageEngine, Windows image decoder, CameraX, OCR, PDF and visual fidelity are **NOT tested**. `Random(seed)` generates synthetic pixel content ONLY, never a cryptographic nonce or QR pairing material.

The test drives real `DurableReceiveJournalV1` via strict `PageWireV1` JSON metadata with SHA-256 and `image/png` MIME, native NTFS RootDirectory-relative stage CREATE/write/read, no-overwrite atomic rename, full byte reread, receipt, live SafeFileHandle read pins, order, read-only restart and single-use token replay refusal. Two distinct page IDs each receive the full 12MP PNG. After closing the journal, one original blob is corrupted on disk and a new read-only `Inspect` must return POISONED. The separate over-cap case must be rejected BEFORE staging without poisoning the ability to accept a later valid page.

## Test-first RED — correcting a false 12MP fixture claim, NOT a product exploit

The first high-resolution push workflow at code SHA `1dc15c4b7c89d84e5ad576d72cd3540d9945d2ee`, Windows run `43497103546` job `132132963203`, 8/8 SUCCESS, generated **3264 x 2448 = 7,990,272 pixels (7.99MP)**, PNG bytes `23,976,987`, two pages, elapsed `949ms`. It was incorrectly **labeled** 12MP in the fixture/log. That historical PASS proves only a ~8MP **PNG byte-receive test**, NOT 12MP. The mislabel was discovered and explicitly recorded as an erratum in the Drive report rather than silently replaced.

A test-first pixel-count assertion was added at `62e6c5cefed11f31104be24b89c79321e189d916`. It initially triggered a **compile/harness** FAIL because C# constant folding detected an unreachable return path: workflow `43498171888`, job `132136664400`, error `CS0162`. This is not the intended test RED. Converting the dimensions to runtime locals at `bc431be4fa4a3e4891a769c4b062c8a8235dd214` allowed the real expected **test fixture RED**: workflow `43498403962`, job `132137454292`, FAILED with `FAIL: PNG fixture incorrectly labeled 12MP: 7990272 pixels`. This RED corrects test evidence, **not a domain, cryptography or journal security bug**.

## Real 12,000,000-pixel GREEN

Fix source SHA `d00014444225586cb5aaeee955f026b5293aefbe`: dimensions **4000 x 3000 = 12,000,000 pixels**. The deterministic synthetic RGB input retains per-pixel diversity but zeros the first of every three RGB channel bytes and uses `CompressionLevel.Optimal` so the encoded valid PNG stays below the **already existing 32MiB receive cap**. This is deliberately compressible synthetic data; it does not model camera noise entropy or all possible full-resolution files.

Real Windows GitHub Actions push workflow **`43498666527`**, job **`132138362355`**, **8/8 SUCCESS**, log:
- `PASS: REAL NTFS 12MP valid RGB PNG pages=2 dimensions=4000x3000 pngBytesPerPage=28341170 elapsedMs=3204 baselineHandles=245 liveHandles=258 exactNativeReadPins=4 afterDisposeHandles=247 restartPages=2 replayDenied=true offlineTamperPoisoned=true noLatencySla=true`
- The test writes two complete 28,341,170-byte blobs (total **56,682,340 bytes**) through the native stage/receipt contract; returns a trusted read-only two-page ledger after Dispose and rejects a consumed token. Exactly **four real open native page pins** exist for the two confirmed pages during the session. No claim of performance SLA or production scanned-image quality.
- `PASS: REAL NTFS over-limit PNG dimensions=4096x3072 bytes=37757636 hardCapBytes=33554432 rejectedBeforeStaging=true validRetryAccepted=true noLatencySla=true`.
- Over-limit input is itself a **valid** 4096x3072 PNG using a no-compression, full-entropy synthetic byte stream. The existing **33,554,432-byte / 32MiB** limit rejects it before a staging entry can be created, and the valid 12MP input is accepted afterwards. This is both a security admission gate and a possible real product limitation for high-entropy/full-resolution PNGs; no cap increase is silently made.

## Process-global handle accounting regression and correction

The initial expanded SelfTest shared suite at code SHA `1dc15c4b7c89d84e5ad576d72cd3540d9945d2ee` had a real Windows bootstrap FAIL, workflow `43497111909`, job `132132994573`: `FAIL: live Windows NTFS pin handle budget 100 baseline=346 live=487 expectedPins=200`. This was **not a new access-token resource leak or failed native pin**: the process-global Windows `Process.HandleCount` can decrease when other CLR/OS handles close, so a lower bound `2N-32` wrongly inferred exact pin count. It is a **test-harness RED**.

Source fix commits `15b0cc21d38c71c235ad9025e19a04742de398ff`, `1c7468d9ca5784756e797d7e1b060896e6e5a918`, `afd26e7af3aa05d4fe9a3e3572eaa04e5676bd66`: internal `LivePinnedAssetHandleCount` directly counts open, non-invalid **actual Native SafeFileHandles** for the live page blob and receipt pins, asserting exactly `2N`. `Process.HandleCount` remains useful only for a **global upper resource bound** and post-`Dispose()` release check, not as a fake exact lower bound. Both standard and high-res tests apply this distinction. No public API expansion, permissions weakening, new production write path or new third-party dependency.

## Isolation and remaining release gates

New PUBLIC GitHub workflow `.github/workflows/windows-hires-synthetic-png.yml` runs only on this PUBLIC branch for source/workflow pushes or explicit dispatch; `windows-latest`, `dotnet 10.x`, 25-minute timeout, `permissions: contents: read`, `persist-credentials: false`, synthetic-only fixtures and no production credentials. Its 12MP test is a **separate push workflow at the source SHA**, not the six normal PR-run gates. Later docs-only commits must independently pass six PR workflows and must not claim this specialized push run was executed at the docs SHA.

**NOT RUN / NOT VERIFIED:** actual camera, ImageEngine decoding/perspective/enhancement, Android physical device fd-provider/UID, true OCR, searchable PDF, release packages and real 500/1000 12MP pages; real NTFS quota ENOSPC, directory metadata fsync, sudden OS/power loss, or arbitrary same-SID malicious offline writer. Previous extended 500/1000 page probes used **three bytes per page**, not full-resolution images.

**RELEASE NO-GO:** 42 Maven child-POM/transitive license rights reviews, Windows SDK BuildTools EULA/REDIST, rights-holder root LICENSE, complete THIRD-PARTY NOTICE/LICENSES/SBOM, QR secure one-time CSPRNG and pinned HTTPS/WSS, independently complete native Android+Windows scanner features, signing, package smoke and rollback. PUBLIC/PRIVATE isolation preserved.

Independent acceptance categories unchanged: Android native **0/21=0%**, Windows native **0/20=0%**, Android/Windows parity **0/41=0%**, platform foundation **3/6=50%**, PUBLIC structural **4/5=80%**, signed commercial release **0/8=0%**. These are **not** an overall product progress percentage.

**Next priority:** a verified isolated quota-limited NTFS test volume with physical ENOSPC and read-only restart, and an Android physical device check for fd-relative provider support. Separately evaluate the **32MiB high-resolution PNG policy limit**, memory/CPU footprint for real image entropy and Android/Windows transfer parity before increasing any wire limit. Do not declare RELEASE GO or add new dependencies without rights review.

**Final exact-HEAD evidence:** wait for all six normal PR workflows after this documentation commit, verify exact job steps and Android JUnit XML, and append to the Google Drive Raporlar final report. Historical RED/compile FAILs remain correctly attributed.
