# PUBLIC Android single-page JPEG/PNG export — 2026-11-17

## Goal and new product capability
The Android standalone E-Scanner workspace previously exported only PDF.
This app-first slice adds **per-page JPEG and PNG** through the native
Storage Access Framework `ACTION_CREATE_DOCUMENT`. It uses the already
implemented immutable source SHA-256 check, JPEG EXIF normalized
high-resolution decoder, perspective quad transform and 90-degree rotation.
The originals and Windows source code remain untouched.

## Image and provider safety policy
* Each page card offers JPG and PNG actions. The picker returns exactly one
  provider URI, and the callback looks up the original chosen page ID; removed
  or changed originals fail closed. Activity recreation/cancellation without
  a pending page ID cannot export the wrong page.
* Platform `Bitmap.compress` produces JPEG quality 92 on a white background
  (transparent pixels flattened) or lossless PNG preserving alpha. Exported
  image is native resolution, not the 480px thumbnail. Page rotation swaps
  dimensions for 90/270 degrees. No PDF A4 page constraints apply.
* Decode/crop/rotate stay on the existing background IO executor. Bounds
  24MP/8000-edge, preflight for the additional rotation/JPEG bitmap, native
  encoder output header MIME+dimensions check.
* A NEW dedicated private image stage directory has single-process active
  protection and exact UUID stage names; startup removes only stale regular
  file entries, without following symlinks. Partial SAF target may remain on
  crash (NO atomic SAF rollback).
* The pre-existing `VerifiedSafPdfTransfer.copyAndVerify` is a bounded,
  format-neutral byte stream SHA-256/size readback in implementation though
  PDF-named; it is REUSED unchanged for image bytes. SAF target decoder
  header MIME and dimensions are re-verified after SHA readback. Unreadable,
  corrupt, stale or refused provider output fails closed. `"wt"` requests
  truncate, but Android providers do not guarantee atomic/durable commit.
* Pure JUnit tests cover export formats, 0/90/180/270 output dimensions,
  invalid/oversized images, precise MIME+size contracts and private-image
  orphan/symlink/live-stage safety. Native Bitmap compression and
  DocumentsProvider provider behavior are NOT exercised by JVM tests.

## Explicit open gates
No physical Android DocumentsProvider (local/cloud), 1/20/100-page PDF
raster acceptance, PDF target pixels, actual image JPEG/PNG visual QA,
Windows WinRT PDF render/reopen or Windows GUI acceptance available. The
single-page image-export capability is implemented at source level, not
a feature-complete platform-parity claim. Windows equivalent JPEG/PNG
export is still required.
Android Maven NOTICE missing/duplicate resolved dependency row FAIL;
source/transitive license inventory, Windows SDK REDIST/EULA, SBOM,
signing, package acceptance, QR/TLS, OCR/searchable PDF and release
remain **RELEASE NO-GO**.
