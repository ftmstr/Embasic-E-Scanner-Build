# PUBLIC Durable Journal — Ancestor alias, hardlink admission and bounded I/O profile

Date: 2026-11-10. Source-of-truth: PUBLIC ftmstr/Embasic-E-Scanner-Build, development branch fix/pdf-fixture-selftest-20261018, PR #1 OPEN/DRAFT. Initial head: 87e85f636ee8a598dda3d1d35f76666302be3d0c. No private source or secret used; no root product LICENSE, main merge, force push or new third-party dependencies.

## Test-first concrete issue

The previous on-disk adapter verified the **leaf** root's inode/file ID and checked that the leaf was not a symlink/reparse point. It did **not** reject an existing symbolic-link or reparse point in a **parent component**. A nested root reached through an attacker-controlled alias could therefore pass the leaf check. Furthermore, a valid `token.claim` with a second hardlink outside the private directory had the same contents and file ID but could be modified via that second pathname.

Real RED evidence before fixes:
- Windows .NET Foundation run 42883096535, job 130064248506, failure in real self-test log: `FAIL: symlinked ancestor reached private root`.
- Android Kotlin Foundation run 42883097120, job 130064252023, Gradle `:app:testDebugUnitTest` failure. Real log named `ancestorSymlinkMustNotProvidePrivateRoot` and `externalHardlinkToConsumedTokenMustPoisonJournal` as FAILED. These are product-code boundary failures, not remote-service outages. Preserve RED evidence even when later green.

## Fix and verified scope (source facts)

Android `DurableReceiveJournalV1.kt`: the root-identity lookup now traverses every **lexical ancestor** with `NOFOLLOW_LINKS`, requiring a directory and rejecting any symlink. Each record's `safeKey` also requires `unix:nlink == 1` and a regular non-symlink file; if a provider cannot expose this Unix attribute, access **fails closed**. Android actual device / SAF / scoped-storage behavior is NOT VERIFIED.

Windows `DurableReceiveJournalV1.cs`: `GetRootId` traverses every lexical parent using `File.GetAttributes`, rejecting reparse points and non-directories before opening the root handle. File `HandleId` uses built-in Win32 `GetFileInformationByHandle` to require `LinkCount == 1` for stage/blob/receipt/claim file handles. This relies on native .NET/Win32 already present; no third-party dependency was added.

Shared PUBLIC `tests/golden/private-root-alias-v1.tsv` has **two byte-visible adjudication cases**, `ancestor_symlink` (root open REJECT; readonly recovery POISONED) and `external_token_hardlink` (recovery POISONED; next page REJECT). Android JUnit and Windows .NET SelfTest independently consume the **same** fixture. Windows symlink creation may lack runner privilege; any skipped execution must be reported NOT VERIFIED instead of PASS. Hardlink fixture creates a second name outside the private-root directory on the same volume, with no user data.

## Real-file rehash performance probes (no latency target)

Both platform suites now run two **synthetic, real temporary-filesystem** admission/recovery profiles by default: 20 and 100 pages. Each page body is only ASCII `abc` (3 bytes), unique canonical page ID and identical harmless SHA256. Every page invokes the production foundation stage + historical full-ledger audit before and after new page. Tests demand exact final page count and read-only `TOKEN_CONSUMED` status and print `FOUNDATION_PERF_ANDROID_JVM pages=N elapsedMs=X` or `FOUNDATION_PERF_WINDOWS_NTFS pages=N elapsedMs=X` to the GitHub job logs. These are **measured environment-specific run times, not commitments or targets**.

Extended **500/1000 page** probes exist behind explicit process environment flag `EMBASIC_ESCANNER_PERF_EXTENDED=1`, and remain NOT RUN until genuinely executed. At 3 bytes per page they also do not model real full-resolution images or sustained network load. Entire historical blob+receipt recheck before and after each commit creates an O(N²) cumulative I/O pattern; do not infer acceptable 500/1000-page performance from a 20/100 synthetic run. Under disk pressure, sudden power-cut, same-directory hostile write, ACL misconfiguration, rollback/restore and path TOCTOU the production safety claim is **NOT VERIFIED**.

## Exact boundary and unclosed release gates

**NOT VERIFIED:** Windows junction creation and live TOCTOU race with untrusted second writer; POSIX or Windows ACL/effective-owner verification; pinned open directory handles for every operation; parent directory rename during staging; low-disk `ENOSPC` and sudden hard reboot/powercut; Android device provider; real JPEG/PNG full-resolution bounds; CSPRNG-backed QR token and fingerprint-pinned TLS; OCR, searchable PDF, signed APK/AAB/MSIX, actual Windows UI and parity. Source-level ancestor checks and `nlink` checks are not substitute for a provably private app-controlled directory.

**BLOCKED/RELEASE NO-GO:** 42 Maven child POM rights review gaps, Microsoft.Windows.SDK.BuildTools 10.0.26100.4654 EULA/REDIST installer distribution evidence, root product LICENSE rights-holder approval, complete SBOM/THIRD-PARTY NOTICE, release signing and hardware QA.

Do not average separate progress counters: Android native 0/21=0%; Windows native 0/20=0%; combined 0/41=0%; platform foundation 3/6=50%; PUBLIC structure 4/5=80%; signed release 0/8=0%. New bounded security checks and file profiling are platform **foundation tests**, not finished scanner features.

## Next critical independent work

Implement and explicitly verify app-owned private-root creation and owner/ACL enforcement using platform-approved storage and pinned directory handles; exercise real process isolation/attacker-writer races, NTFS junction/mountpoint paths, directory fsync and low-disk/kill/restart. Then run opt-in extended 500/1000 synthetic filesystem profiles separately and real 1/20/100/500/1000 scan pages on target devices. Maintain legal/CI/release NO-GO until independent gates pass.
