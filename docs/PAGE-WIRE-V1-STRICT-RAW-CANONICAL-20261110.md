# PUBLIC page-wire v1 bounded parse→validate→canonical contract (10 Nov 2026)

**Scope/owner:** Sole authorized repository `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, PR #1 remains OPEN/DRAFT. Previous base HEAD was `d789f76d887418f9b03906a2db0db7ffa063fff0`. Source-only / independently authored. No private repository source, real document sample, signing material, root product LICENSE grant, new runtime dependency, or product feature declaration.

## Trust boundary and exact v1 fields

The Kotlin `PageWireV1` and C# `PageWireV1` use deliberately *restricted*, strict ASCII JSON object parsing. A positive return is only a **typed, canonical, untrusted wire metadata value**. Neither platform uses this alone to authorize domain transitions or image admission.

Exactly seven required fields; no unknowns, duplicates, aliases or implicit defaults:
- `protocolVersion`: JSON integer literal **1**, no alternate syntaxes.
- `sessionId`: lowercase nonzero 8-4-4-4-12 hex UUID, **exactly equals trusted caller-provided expectedSessionId**. Not proof of peer identity.
- `pageId`: different nonzero lowercase UUID, not the session UUID. Uniqueness over historical pages is not checked here.
- `order`: unsigned nonnegative JSON canonical integer, fits signed int32.
- `byteSize`: strictly positive canonical integer within signed int64 and **caller-specified maxBytes**.
- `mime`: literal `image/jpeg` or `image/png` ONLY. Not a decoded image guarantee.
- `sha256`: 64 lowercase hex characters of full payload digest, verified separately against the staged complete bytes.

Input byte bound: **1–4096 bytes inclusive**. Only ASCII bytes `0x20..0x7e` and whitespace TAB/LF/CR are allowed. No BOM, malformed UTF-8, non-ASCII Unicode, unescaped control characters, JSON string escapes (including `\\u` equivalence), scalar/nested/array roots, comments, trailing tokens or trailing commas. JSON whitespace and object-key order are accepted, then normalized to exactly one deterministic seven-member ASCII JSON object with no whitespace or escapes. Number coercion, exponent/fraction, leading zero, negative numbers, int32/int64 overflow and booleans/null are not accepted.

The parser fails closed on `status` / `state` / `READY`, `token`, `nonce`, `expiresAt` or ANY additional field rather than copying untrusted remote state into ScanSession. The caller separately supplies the expected session identity and maximum allowed page size. The new parser relies solely on Kotlin/Java and .NET standard libraries; no new licenses or transitive runtime packages are imported.

## Evidence paths

- `android/app/src/main/kotlin/com/embasic/escanner/android/PageWireV1.kt`
- `android/app/src/test/kotlin/com/embasic/escanner/android/PageWireV1Test.kt`
- `windows/Embasic.EScanner.Contracts/PageWireV1.cs`
- `windows/Embasic.EScanner.SelfTest/Program.cs` (new golden matrix loop)
- `tests/golden/page-wire-v1.hex.tsv`: **63 exact byte vectors**; 5 valid variations, 58 rejection vectors. This single file is consumed by BOTH platform tests and absent/missing cases are fatal. `tests/golden/CANONICAL.txt` pins reference output; `tests/golden/README.md` documents byte provenance and security scope.
- `.github/workflows/android-build.yml`, `windows-build.yml`, and `windows-bootstrap.yml`: `tests/golden/**` path triggers ensure future cross-platform parity fixtures re-run both platform checks.

This golden matrix uses only synthetic UUIDs, public SHA-256 of ASCII `abc`, and generated invalid JSON/bytes. It contains no private credentials or user images. Independent local Kotlin compiler (1.9) exercise completed 5/5 accept, 58/58 reject, and a separate compiler/JUnit-like stub-harness exercise completed two test methods. These are **LOCAL supplementary evidence only**. Real Android JUnit and .NET SUCCESS MUST be established from final SHA GitHub Actions run/job/step/log; a PASS must never be inferred from source-only checks.

## Still not proven — release NO-GO

Even correct checksum and typed metadata DO NOT demonstrate authenticated HTTPS/WSS, QR certificate fingerprint pinning, one-time token secrecy/expiry/replay handling, duplicate page order/restart policy, actual IMAGE signature, pixel/decode limit, staging atomic replace, TOCTOU resistance, UI parity, offline OCR or searchable PDF. The caller must not infer `RECEIVED`, `PROCESSING`, `READY`, or `EXPORTED` from a parse result. Full input admission and replay/session state-machine remain separate adapters requiring tests.

Legal blocking work from previous reports is unchanged: 42 selected child Maven POM legal review rows open; `Microsoft.Windows.SDK.BuildTools 10.0.26100.4654` signed legal EULA/REDIST and actual installer file rights not verified; third-party NOTICE/LICENSES and SBOM incomplete; no rights-holder-approved product root LICENSE. Preflight workflow's SUCCESS is not product license clearance.

As of this foundation task, verified **native features 0/21 Android + 0/20 Windows = 0/41 combined (0%)**, platform foundation **3/6 (50%)**, PUBLIC structural **4/5 (80%)**, signed release **0/8 (0%)**. These independent gates cannot be averaged into fictitious progress.

## Next critical independent task

Design a **session-scoped durable receive/staging state machine** with one-time token/expiry/replay admission, explicit expected page/order uniqueness, full image magic/safety-limit decode, authenticated TLS pinning and crash/retry handling. Continue licensing rights review separately. Keep feature/parity/release NO-GO until actual target-device tests and rights gates pass.
