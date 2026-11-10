# Durable Receive Journal V1 — live historical ledger admission hardening

Date: 10 November 2026. Authorized PUBLIC only: `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, PR #1 OPEN/DRAFT. Initial live HEAD: `83c5cb8248ea587f8569d1ed63c7fb5fffae0d09`. The previous full on-disk journaling tour was already completed at initial HEAD; this turn does **not** repeat initial CREATE_NEW token, staging or recovery implementation.

## Concrete regression and red evidence

The existing read-only `inspect` method correctly classified a modified previously committed blob, receipt, claim, unknown file or orphan as POISONED. But the **live `commit` method** did not verify the historical sequence before appending another valid page. Test-first, shared `tests/golden/durable-receipt-v1.tsv` added 7 distinct adversarial traces, raising canonical golden from 30 cases/64 decisions to **37 cases/90 decisions** on **both Kotlin and C#**.

Real GitHub Windows .NET Foundation RED run **42862804603**, job **129993134255**, failed in `Run synthetic contract assertions` on `FAIL: prior_blob_corruption_blocks_next action COMMIT1`. This was a deliberate test-first exposure of a real acceptance bug, not a runner outage. Do not erase or relabel this FAIL; later green CI must show its repair.

## Fix and new invariant

Both `android/app/src/main/kotlin/com/embasic/escanner/android/DurableReceiveJournalV1.kt` and `windows/Embasic.EScanner.Contracts/DurableReceiveJournalV1.cs` now read-only re-audit **all existing token and page receipts/blobs** before a new `commit` can call the in-memory page gate. The snapshot must be `TOKEN_CONSUMED`, and its confirmed page count must equal the current in-memory gate's confirmed count. Otherwise this instance transitions to permanently stopped (fail-closed). After stage write/rename, payload reread, receipt creation and gate confirmation, the **full chain is re-audited once more** before commit returns success. No stale identity, alien file, torn earlier receipt or changed previous blob silently grants a later page.

New test scenarios:
- corrupted prior page blob, then new page commit must reject;
- corrupted prior receipt, then new page commit must reject;
- damaged token claim before first page, must reject;
- unknown file inserted after token claim, must reject first page;
- unknown file added after page 0, must reject page 1;
- receipt index gap added after page 0, must reject page 1;
- stale stage temporary added after page 0, must reject next page.

Both systems use their already-developed bounded read-only `inspect/Inspect` and no new runtime dependency. The isolated test-private directories and public synthetic bytes avoid customer/secret data.

## Explicit limits and non-guarantees

Re-auditing a sequence is not a filesystem transaction or OS ACL boundary. Attackers holding a competing write handle to the same private directory can still race a snapshot vs. stage/rename; verified platform-private root ownership and a pinned directory handle remain mandatory. Directory `fsync` semantics, simulated sudden power loss, file rollback/restore replay, low-disk errors, symlink/hardlink/junction and third-party mounts are **NOT VERIFIED**. In-memory session grant and on-disk token claim remain distinct and cannot authorize future resume. The current full historical rehash before and after every page is deliberately conservative but may have quadratic cumulative I/O costs; 20/100/500/1000-page performance is **NOT VERIFIED**. Do not market it as a scalable or atomic production receiver.

Windows target remains **C# / .NET 10 / WinUI 3** and Android Kotlin/Compose, per current PUBLIC README. Real TLS fingerprint pinning/QR CSPRNG, full-resolution streaming and safe image decode, real ScanSession admission, OCR/searchable PDF, native end-to-end and physical device release QA are still NOT VERIFIED.

**Legal release NO-GO:** Owner-approved root LICENSE absent; 42 Maven child POM direct licensing review open; Windows SDK BuildTools exact EULA/REDIST and installer rights not verified; full SBOM/NOTICE/licenses/signing/rollback absent. Separate percentages: Android native **0/21=0%**; Windows native **0/20=0%**; combined parity **0/41=0%**; platform foundation **3/6=50%**; PUBLIC structure **4/5=80%**; signed release **0/8=0%**. Do NOT average independent gates into invented overall completion.

## Next critical step

Replace path-based snapshot boundaries with a provider-specific directory handle and least-privilege directory ACL / Android app-private storage ownership enforcement, plus explicitly reproducible low-disk/process-kill/restart and rename durability tests. Separately build/review pinned HTTPS/WSS QR session and image-safe decoder. Only claim verified acceptance from final-head completed GitHub Actions, never code review alone.
