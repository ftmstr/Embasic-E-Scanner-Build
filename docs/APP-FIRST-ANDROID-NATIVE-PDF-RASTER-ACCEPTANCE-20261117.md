# Android target PDF native rendered-page acceptance gate — 2026-11-17

## Initial state
PUBLIC `ftmstr/Embasic-E-Scanner-Build` branch
`fix/pdf-fixture-selftest-20261018`, start SHA
`6022b22abfce9c9d39da5bce16e1cfbf00f5f0f6`, Draft PR #1 OPEN.
Android already stages `PdfDocument`, checks a reopened stage page count,
writes SAF `ACTION_CREATE_DOCUMENT` using `"wt"`, readbacks exact byte
length and SHA-256, then checks the target PdfRenderer page count.
However, opening a PDF and counting pages does NOT demonstrate that each
individual page has expected geometry or can be rasterized. For a corrupted
image resource or wrong page geometry the app could wrongly report success.

## App-first vertical slice
* `PdfRasterPlan`: independent pure Kotlin contract for A4 595x842
  (PDF points), 1..100 exact ordered pages, a fixed 192x272 ARGB pixel buffer
  and a page-indexed SHA-256 raster digest. Unit tests cover valid 1/20/100
  geometry, invalid page counts, swapped A4, mutation detection, ordering
  and missing/duplicate/oversized page buffers.
* `PdfRasterGate`: use the NATIVE Android `PdfRenderer` to render EVERY
  staged PDF page and EVERY SAF TARGET PDF page to a bounded 192x272
  bitmap. Check each page geometry before rendering; turn actual ARGB
  pixels into a page-indexed digest; compare the two ordered render receipts.
  A failure is fail-closed before reporting "PDF doğrulandı". Descriptor,
  PdfRenderer, every opened page and single bounded bitmap are closed/
  recycled even on failure. It runs off the UI thread.
* This supplements, does NOT replace, full-byte SHA-256 readback,
  non-destructive originals/quad/rotation, `PrivatePdfStageCache` cleanup
  and existing SAF target rules. No new dependency or framework.
* A PDF with legitimately white/blank pages remains valid: raster content
  is not forced nonwhite. Low-res raster digest equality of two renderings
  confirms native decoder consistency and page order; it is NOT proof of
  original photo fidelity, correct OCR, full-resolution visual parity or
  rendered-pixel golden acceptance on a physical device.

## Limitations and gates
A physical Android/API26–36 device and real DocumentsProvider was NOT
available in this execution; `PdfRenderer.render` source compilation and
pure JVM digest tests do not constitute a native runtime PASS. Rendering a
provider's descriptor can fail if it does not support seekable access, and
the export will report failure. Rendering 100 pages can add time but bitmap
allocation is constant at 192*272 pixels with 192*272*4 byte scratch.
No network or third-party dependency, no image content sent outside device.

Windows WinUI3 source compilation is not WinRT PDF runtime/visual QA;
actual Windows `Windows.Data.Pdf` open/render remains NOT VERIFIED/BLOCKED.
Android native SAF atomic replacement/rollback remains unimplemented.
Maven NOTICE resolved dependency inventory FAILURE, 42 POM license,
WinAppSDK REDIST/EULA, SBOM/third-party notices, signing/packaging and
physical device acceptance remain RELEASE NO-GO.
