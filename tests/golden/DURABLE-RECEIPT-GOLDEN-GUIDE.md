# Durable receive journal V1 — actual file-system golden traces

Canonical matrix: `tests/golden/durable-receipt-v1.tsv`; it is consumed directly
by Android `DurableReceiveJournalV1Test` (JUnit/Gradle on Linux JVM) and
Windows `DurableReceiveJournalSelfTest.Run` (real .NET on Windows CI).
Every row contains five TAB-separated fields:
`id<TAB>actions<TAB>A_or_R<TAB>recovery_status<TAB>confirmed_pages`.
It has **37 non-comment rows with 90 ordered decisions**. Both suites reject
missing/duplicate cases or changed results. No real documents or secrets.

The cases use pre-created, disposable test-private session directories and
synthetic `abc` payloads. They exercise exclusive claim marker, consumed token
after new object instance, full per-page stage/write/readback/receipt, consecutive
order and unique page ID, corrupt/truncated body, orphan temporary/blob/receipt,
torn claim or receipt, unexpected filenames, a gap in the receipt series, session
expiry and maximum page count. Both suites additionally race **24 independent
instances** for the same `CREATE_NEW token.claim` path: exactly one winner is
required.

Recover statuses:
- `FRESH`: verified empty trusted directory only
- `TOKEN_CONSUMED`: fully valid claim and exact receipt/blob chain, **never
  authority to reuse token or resume transfer**
- `POISONED`: any unknown, orphan, torn, invalid or substituted record

**Limitations**: real Android device provider and Windows untrusted-writer ACL/
junction/hardlink adversarial tests remain NOT VERIFIED. Controlled orphan and
corruption fixtures do not simulate actual process kill or sudden power loss.
`FileChannel.force(true)` / `FileStream.Flush(true)` do not constitute a
portable fsync of a directory rename. This adapter is NOT the ScanSession,
TLS pinning, QR CSPRNG or image decoding implementation. App-private
directory ownership and access isolation is a mandatory composition-root
precondition, and there is no self-service tombstone deletion.

See `docs/DURABLE-RECEIVE-JOURNAL-V1-RESTART-20261110.md`.
**RELEASE NO-GO** until native apps, protocol security, product licensing and
hardware release gates independently pass.

## Live ledger revalidation (additional 7 adversarial traces)

Seven new single-session test traces corrupt or add an unknown file *after*
successful token admission or page-zero receipt, and then attempt another
page commit. The receiver must reject that next commit even if the new page
itself has a valid hash and order. The adversarial fixture names are
`prior_blob_corruption_blocks_next`,
`prior_receipt_corruption_blocks_next`,
`token_claim_corruption_blocks_first`,
`unknown_after_claim_blocks_first`,
`unknown_after_page_blocks_next`,
`gap_after_page_blocks_next` and
`stale_stage_after_page_blocks_next`.
This is a separate property from read-only restart inspection: unsafe
pre-existing history must block *live* progress as well.

Before and after each page commit the adapters now inspect the entire
receipt+blob sequence, compare its page count to the in-memory gate and
fail-closed poison the instance upon mismatch. This catches static tampering
and interrupted/orphan entries without silently appending more pages.
**NOT PROVED:** a hostile same-directory writer racing between inspection
and a stage/rename; no portable directory fsync or full power-cut guarantee.
Review the cumulative O(pages × historical byte volume) re-audit cost at
20/100/500/1000 pages before allowing production use.
