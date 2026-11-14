# Receive Gate V1 — shared parity trace guide

**Version:** 1, synthetic-only, 10 Nov 2026. Canonical source:
`tests/golden/receive-gate-v1.tsv`. Android `ReceiveGateV1Test` and Windows
`Embasic.EScanner.SelfTest` execute the same **38** scenarios totaling **95**
ordered actions; both fail if a row is missing, duplicated or produces a
different decision, phase or confirmed-page count.

Each non-comment row has exactly five TAB-separated fields:
`caseId | action@trustedTime[,action@trustedTime] | A_or_R[,A_or_R] |
finalPhase | confirmedCount` (vertical bars shown for readability only).
`A` means the in-memory guard accepted the proposed action and `R`
means rejected. The fixture uses issue=1000 ms, expire=2000 ms and only
harmless publicly known token/digest and `abc` bytes. No production
QR token, key, network endpoint, physical document or user data.

The fixture checks only caller-trusted policy and an *in-memory*
state-machine guard: one-time token admission, expiry, clock rollback,
strict page identity/order, pending proposal and reread hash/size
matching, cancel and concurrent stage/token races. Neither a `STAGED`
phase nor a successful reread call proves durable, atomic disk writes,
image decodability, TLS authentication/fingerprint pinning, replay after
restart, or a production ScanSession domain transition. All of these
remain **NOT VERIFIED/NO-GO**, including commercial licensing.

Existing `page-wire-v1.hex.tsv` (63 raw byte examples) is retained
unchanged and must continue to pass on both platforms.

For security rationale and release blockers, see
`docs/RECEIVE-GATE-V1-SESSION-ADMISSION-20261110.md`.
