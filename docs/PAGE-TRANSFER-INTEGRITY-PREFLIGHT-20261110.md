# PUBLIC page-transfer envelope integrity preflight — 10 Nov 2026

**Scope:** PUBLIC `ftmstr/Embasic-E-Scanner-Build`, branch
`fix/pdf-fixture-selftest-20261018`. PR #1 remains DRAFT.
This is an independently authored Kotlin/C# **foundation contract**, not a
working QR pairing, wireless camera, TLS server, WinUI scanner, image decoder,
ScanSession integration, offline OCR or PDF exporter.

## Independent platform implementations

- Android: `android/app/src/main/kotlin/com/embasic/escanner/android/PageTransferIntegrity.kt`
- Windows: `windows/Embasic.EScanner.Contracts/PageTransferIntegrity.cs`
- Real platform test entrypoints:
  `android/app/src/test/kotlin/com/embasic/escanner/android/PageTransferIntegrityTest.kt`
  and `windows/Embasic.EScanner.SelfTest/Program.cs`

Both implement the same **typed-envelope integrity preflight**, requiring
a non-nil lowercase, 36-character 8-4-4-4-12 hex UUID for each distinct
sessionId/pageId, nonnegative page order, strict `image/jpeg` or `image/png`
MIME token, lowercase 64-character SHA-256, strictly positive declared size,
strictly positive caller-selected byte limit, and declared size <= that
limit. A complete byte array must equal the declared byte count and have
the declared SHA-256 digest. Digest equality is constant-time at the digest
comparison boundary. No IMEI/MAC/Android ID. No new external runtime
dependencies are introduced.

Both platforms use the same harmless synthetic input `abc` with digest
`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`,
session `01234567-89ab-4cde-8f01-23456789abcd`, page
`11234567-89ab-4cde-8f01-23456789abcd`, order 0, declared byte
size 3 and 1024-byte test ceiling. Corruption, truncated/extra bytes,
mismatched hashes, wrong integer limits, malformed UUIDs, wrong MIME,
nil identifiers and identity collisions are rejected.

**Important trust boundary:** This preflight accepts a correctly hashed
byte sequence marked `image/jpeg` even if those bytes are not a valid JPEG.
It does **not** sniff or decode image formats, parse/validate untrusted raw
JSON, protect against token replay, authenticate the peer, pin a TLS
certificate, enforce maximum image pixels, persist an immutable asset,
or prevent TOCTOU between verification and write. A positive result MUST
NOT be treated as `RECEIVED`/`READY` domain admission. Subsequent
steps require strict canonical wire parsing, TLS/fingerprint/token checks,
MIME signature and safety-limited full image decode, staging, session
binding, unique page index, and state-machine validation.

The max byte limit is a **caller policy input**, not a globally approved
size quota. Values can be changed only through explicit callers with
separate tests; neither implementation grants an unlimited default.
The UUID check only normalizes the textual representation and rejects nil;
it is not evidence of identity authenticity or a UUID version policy.

## CI, legal and release gates

Existing workflows `android-build.yml`, `windows-build.yml` and
`windows-bootstrap.yml` include these paths through `android/**` and
`windows/**`. GitHub Actions final-head jobs and executed JUnit cases must
be verified separately; a source commit is not test PASS.
The underlying Android/Windows production feature counts are **unchanged**:
0/21 Android native, 0/20 Windows native, 0/41 combined. Foundation platform
gates 3/6, PUBLIC structure 4/5, signed release 0/8 (subject to evidence
updates). Root product LICENSE must not be fabricated without owner rights
approval. 42 Maven child POM metadata legal reviews, Windows SDK
BuildTools 10.0.26100.4654 rights/REDIST, NOTICE/SBOM, secure QR/TLS,
production import/OCR/PDF, physical target QA and signed release stay OPEN.

## Next work

Prioritize a strict bounded versioned raw-wire parser and multi-platform
canonical-fixture parity (not merely two parallel happy paths); connect this
preflight to a safe receive/staging state machine only after pinned TLS,
one-time token/replay and source integrity gates exist. In parallel, close
exact supplier licensing and Microsoft SDK redistribution evidence.
Never sync a PRIVATE repository or claim a product release.
