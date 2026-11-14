# PUBLIC page-wire-v1 byte-exact golden fixtures

`page-wire-v1.hex.tsv`: each non-comment row is exactly `case_id<TAB>PASS|REJECT<TAB>lowercase_hex_bytes`. The hex represents the **entire untrusted wire byte sequence**, not parsed JSON. Android `PageWireV1Test.kt` and Windows `Embasic.EScanner.SelfTest/Program.cs` read these same bytes. Missing, duplicated or truncated fixture sets cause test failure.

Version 1 has exactly seven required members: `protocolVersion` (integer 1), `sessionId`, `pageId`, `order` (nonnegative int32), `byteSize` (positive int64), `mime`, `sha256`. The caller MUST supply a trusted canonical expected session ID and a strictly positive maximum byte count; neither is authorized by the JSON. Strings are literal ASCII with **no escapes** (even semantically equivalent escapes are rejected); integers cannot contain leading zeros, signs, fractions or exponents. Key order and surrounding JSON whitespace may vary, but canonical output always uses the exact seven fields in one fixed order. Unrecognized members, including `status`, `state`, `expiresAt`, `token`, `nonce`, and any arbitrary metadata, are rejected. This intentionally accepts a strict subset of JSON; it is NOT a general-purpose JSON parser.

A valid envelope is **metadata only**, not a camera, transport or ScanSession transition. For actual page import, full staged-body hash/size check, TLS fingerprint pinning, one-time token/replay/expiry validation, safe image header/decoder/pixel limit and an atomic state-machine admission gate remain independently necessary.

No real customer data, private repository source, secrets or third-party dependencies. `CANONICAL.txt` is an ASCII canonical example; both platform tests assert the same independently specified canonical result.
