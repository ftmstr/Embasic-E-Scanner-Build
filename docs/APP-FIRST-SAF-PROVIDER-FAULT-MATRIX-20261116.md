# PUBLIC SAF provider fault matrix — 16 November 2026

## Purpose and code boundary

Embasic E-Scanner Android's `VerifiedSafPdfTransfer` already writes a staged,
locally validated PDF to an Android Storage Access Framework (SAF)
`ACTION_CREATE_DOCUMENT` URI and requires a closed-output destination byte
readback (length/SHA-256) plus platform `PdfRenderer` page-count validation.
The imported original and the Windows WinUI3 PDF path are unchanged.

SAF provider `InputStream.read(byte[],...)` implementations are specified to
return at least one byte or EOF when a positive-length buffer is supplied.
Nonconforming/cloud providers may repeatedly return 0, causing the preexisting
`digest` loop to spin indefinitely. This code adds a fail-closed 16-consecutive-
zero-read cap; a positive read resets the cap. The source-file copy loop receives
the same cap as defensive coding. There is **no reliable hard timeout** for a
provider that blocks inside a single `read()` or `write()` call, and no
assumed provider atomicity or durability.

## Exact synthetic JVM provider test matrix

* Append-only SAF provider retains previous user bytes: reject final SHA/size.
* Cloud-stale readback after a fully closed successful output: reject.
* Provider output `close()` fails: do not open target or claim success.
* Provider readback throws midstream: reject even if some bytes are valid.
* Provider returns 0 indefinitely during `InputStream.read(byte[])`:
  reject after precisely 16 calls, and close input.
* Provider produces three transient zero-byte reads before resuming:
  accept only after complete SHA/size match.
* Private staging file mutates after initial SHA and before copy:
  reject; do not open target for validation.
* Synthetic 1, 20 and 100 page-labelled staged byte batches: bounded
  streaming, exact count/hash readback across multiple sizes.
  These batches are **not real PDFs** and do not validate the native PdfRenderer.

Existing six JVM SAF tests remain. No dependency added; all tests run under
Android Kotlin Foundation `testDebugUnitTest` and not an emulator.
The Android Compose app's visible user confirmation remains gated by target
SHA-256 and actual `PdfRenderer` page-count check, unmodified.

## Nonclaims and blockers

No physical Android DocumentsProvider (local/cloud), real storage-exhaustion
or restart harness was available in this CI environment. Android SAF target
atomic replacement **NOT IMPLEMENTED**, and provider crash may still leave a
partially written document. Windows physical WinUI3 GUI/PDF runtime smoke
remains **NOT VERIFIED/BLOCKED**. Android resolved Maven NOTICE license
inventory remains a separate CI **FAILURE**, 42 POM rights, third-party
NOTICE/SBOM, WinAppSDK REDIST/EULA, signing, real APK/AAB and rollback gate
remain **RELEASE NO-GO**. These JVM fault tests do not establish Android /
Windows visual pixel parity, OCR/searchable PDF, camera scanning or secure QR.
