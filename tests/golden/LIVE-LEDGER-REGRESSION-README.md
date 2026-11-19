# Durable receipt live-admission parity evidence — 10 November 2026

The initial `DurableReceiveJournalV1` adapter already existed at PUBLIC HEAD
`83c5cb8248ea587f8569d1ed63c7fb5fffae0d09`. This new, distinct test
suite extension is a **test-first live-ledger corruption check**, not a repeat
of the earlier creation/restart implementation.

The single canonical fixture `durable-receipt-v1.tsv` now contains **37**
scenarios with **90** ordered expected decisions, consumed by both Android
JUnit and Windows .NET SelfTest in CI. It retains every former scenario and
adds seven regressions for tampering with previously accepted blobs, receipts,
the original claim marker, inserted unknown entries, forged index gaps and
stale temporary-stage entries before attempting the next valid page.

**Recorded RED:** GitHub Windows Foundation run `42862804603`,
job `129993134255` returned failure:
`FAIL: prior_blob_corruption_blocks_next action COMMIT1`.
The prior implementation admitted that next page despite corrupt history.
Android pre-fix test was also reported failing in actual CI. Keep these
historical RED records even after subsequent corrected SUCCESS.

**Fix:** Both independently authored Android Kotlin and Windows C# adapters
call their existing *read-only full receipt-chain inspector* immediately
before a new page proposal and once more after committing a new receipt.
A missing, altered, extra or out-of-sequence prior entry or a mismatch with
the in-memory confirmed-page count must permanently poison that instance.
No external runtime dependencies or non-synthetic content were imported.

**Limits:** This guards against *static* prior corruption visible to a
trusted private-root inspector. It does NOT defeat a same-directory hostile
writer racing after the scan, provide directory fsync or guaranteed sudden
power-loss durability, verify a production storage provider's access rights,
authenticate a TLS fingerprint, decode actual images or grant ScanSession
domain acceptance. Re-reading the whole history before/after each commit may
have **quadratic cumulative disk I/O**; 20, 100, 500 and 1000-page performance
is NOT VERIFIED. Physical Android, Windows packaging, licensing, signing,
SBOM and rollback remain release NO-GO gates.

This README is a trigger under `tests/golden/**`, so the final HEAD
must rerun Android, Windows and source/preflight validation before claiming
any terminal CI status. If the latest run is queued or unfinished, report
NOT VERIFIED rather than assuming PASS.
