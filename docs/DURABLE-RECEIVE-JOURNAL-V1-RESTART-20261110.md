# PUBLIC Durable Receive Journal V1 — bounded staging, replay tombstone and restart recovery

Date: 10 November 2026. Source of truth: PUBLIC `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, PR #1 DRAFT (not merged). Baseline before this tour: `5b950956abfa5832371d98d8b4f4bbfa9de3166d`. This is a **separate, conservative local filesystem adapter** for the pre-existing `ReceiveGateV1` and `PageWireV1` contracts; it is NOT a finished QR/TLS session, native camera feature, domain acceptance or release approval.

## Trust boundary

The caller supplies a **pre-created, private, single-session application-owned directory**, canonical expected session UUID, SHA-256 of a cryptographically generated 256-bit QR token *string*, issued/expiry times, per-page maximum size and maximum page count. The disk adapter NEVER generates a token, authenticates a network peer or silently resumes an interrupted session. It refuses missing/non-directory/symlink-or-reparse roots where the platform identity backend can verify them. Android uses `BasicFileAttributes.fileKey` (requires a non-null key; otherwise FAIL CLOSED); Windows uses Win32 `GetFileInformationByHandle` with 64-bit file index/volume serial and `CreateFileW` opening the directory handle without following a reparse-point root. It compares file IDs around staging rename and reread. No third-party dependencies or sensitive data.

The app-private directory and its ancestors **MUST NOT** be writable by a malicious local process. Path swap/hardlink abuse by a hostile same-directory writer, directory entry durability after sudden power loss, and arbitrary Android filesystem provider guarantees are NOT VERIFIED; the code does not promise portable atomicity against these threats. Windows NTFS behavior is tested on CI Windows runner; Android unit tests execute on a Linux JVM and are NOT proof of Android-device provider semantics.

## Token and receipt protocol

- One-time token: SHA-256 digest verified in constant time before writing a CREATE_NEW `token.claim` tombstone. The ASCII marker records `v1|sessionId|tokenSha|issuedAt|expiresAt\n`; file data is flushed to storage before the in-memory gate is authorized. The raw token is **not stored**. An existing marker, even torn, prevents repeat token claim; torn markers poison recovery.
- Staging: in-memory `ReceiveGateV1` must first allow the exact PageWireV1 session/order and complete payload. The file backend bounds stage payloads to **32 MiB** (provisional foundation limit, NOT full-resolution guaranteed capacity). Stage file `stage-0000.tmp` is created with no overwrite, written and force-flushed, reopened without following symlinks/reparse points where supported, and byte-for-byte checked against the original buffer. Stage file identity is checked.
- Commit: stage is renamed to `page-0000.blob` without requested replacement and re-opened and SHA-256/length verified. Then a CREATE_NEW per-order `page-0000.rec` receipt is force-flushed: `v1|order|pageId|byteSize|mime|sha256\n`. Only after this local receipt does in-memory `confirmReread` advance the counter. Failed writes poison the *active instance*, rather than granting a potentially unsafe retry.
- Restart: `inspect/Inspect` is **read-only**. Empty app-private root → FRESH. Exact token marker plus consecutive canonical receipt+blob chain, correct checksums, unique page IDs and no other entries → TOKEN_CONSUMED with count. Unknown files, orphan temp/blob/receipt, missing order, corrupt/truncated marker, wrong checksum or symlink → POISONED. No consumed session is allowed to authenticate or resume on another object instance. Under uncertain crash state, the operator must start a **new distinct session directory/token**, not silently recover old token rights.
- Retention: files are intentionally left untouched by the adapter. The host application must add a carefully scoped, user-authorized GC/cleanup policy later; deleting a claim tombstone could permit replay in the same session namespace, so deletion requires an independently trusted session-retirement protocol.

## Cross-platform real filesystem QA

`tests/golden/durable-receipt-v1.tsv` holds **30 shared synthetic traces** and **64 ordered decisions**. Android `DurableReceiveJournalV1Test.kt` and Windows `DurableReceiveJournalSelfTest.cs` must consume the SAME scenarios. Examples: empty root, fresh claim, double claim, restart replay, wrong token, valid page chain, duplicate page ID/order, out-of-order, wrong/partial payload, foreign session, torn receipt, mutated blob, orphan pending stage, unknown file, empty claim, missing-order gap, expiry and page cap. Both platform suites separately exercise invalid roots / max-size rejection, and a 24-instance same-path token claim race. Symlink root tests require privilege on some Windows runners: lack of privilege must be labeled NOT VERIFIED, never PASS. No real customer documents or secrets; samples use ASCII `abc` and the previous openly synthetic 64-'a' token.

CI must separately establish Windows build+test on Windows and Android JUnit on Linux, then report exact run IDs/job steps/failures; local source code alone is NOT proof. Prior ReceiveGateV1 38/95 trace and raw PageWireV1 63-byte fixture suites must remain passing.

## Security limitations / release gates

**NOT VERIFIED:** sudden power cut at directory-rename boundary; live malicious filesystem writer; session trash cleanup authority; Windows junction/hardlink/ACL adversarial under non-admin local accounts; Android device SAF/private provider; truly streaming multi-hundred-megabyte image capture; image MIME header and decode geometry/limits; TLS fingerprint pinning; CSPRNG production token generation; replay proof across backups/restores; authenticated transfer/ScanSession READY/PDF. NO production native parity claims.

**BLOCKED / RELEASE NO-GO:** owner-approved root product LICENSE, 42 unresolved Maven child-POM legal review rows, Windows SDK BuildTools exact EULA/REDIST and installer file-rights, SBOM/THIRD-PARTY NOTICE, target-device smoke, signed APK/AAB and Windows installer, rollback.

Progress counters remain independently **Android native 0/21=0%; Windows native 0/20=0%; combined 0/41=0%; platform foundation 3/6=50%; PUBLIC structural 4/5=80%; signed release 0/8=0%**. Additional framework contracts and synthetic CI do not constitute finished product features.

## Next highest-value work

Bind a platform-approved private storage root and strict directory ownership/ACL to a crash-recovery/retirement policy; test real fsync/rename and symlink/junction races, low disk and power-cut interruption, then incorporate an authenticated pinned TLS/one-time QR pairing adapter and safe image decoder. Run device parity tests and separately close all legal gates before any release.
