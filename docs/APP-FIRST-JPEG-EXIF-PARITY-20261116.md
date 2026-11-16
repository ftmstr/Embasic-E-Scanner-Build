# APP-FIRST JPEG EXIF ORIENTATION PARITY — 2026-11-16

## Confirmed PUBLIC starting point

Branch fix/pdf-fixture-selftest-20261018, PR #1 Draft/OPEN. Starting SHA 372effb8f56239e5092aeb0c7fbbeb84f9b2708d; previous 12MP report and 7 exact-SHA GitHub CI jobs verified (6 SUCCESS, Android Kotlin Foundation NOTICE partial inventory FAILURE). No PRIVATE/main changes, no force/merge/root LICENSE edits.

## Concrete bug and production-path correction

Windows RasterPdfWriter.DecodeRgbAsync already uses Windows.Graphics.Imaging BitmapDecoder with **ExifOrientationMode.RespectExifOrientation** and OrientedPixelWidth/Height, while Android BitmapFactory preview and PdfDocument export decoded raw JPEG pixel axes. For EXIF 5/6/7/8, portrait landscape and manual 4-corner crop could be inconsistent with Windows, despite the same integer quad recipe.

A JVM-compatible ExifOrientationRecipe maps all eight TIFF orientation tags (including mirrors/transpose) to oriented pixel coordinates and output dimensions. **tests/golden/exif-orientation-v1.tsv** is ONE synthetic golden fixture of 16 source-pixel corner cases, referenced by Android JUnit and Windows .NET RotationSelfTest. Geometry rejects invalid tag/oversized or invalid source, and out-of-image coordinates. No new dependencies.

Android's API26+ system android.media.ExifInterface reads private **JPEG** EXIF orientation. ExifBitmapNormalizer uses Android Canvas/Matrix exact integer right-angle/mirror maps to normalize working bitmaps in both decodeBounded thumbnails/manual 4-corner workspace dialog AND decodeForExport before 12MP perspective correction and the user 90° recipe. The immutable asset, hash, and persisted quad coordinates are NOT rewritten. The export path factors the extra 4-byte/pixel normalized bitmap into the predecode heap estimate and fails closed when unavailable. No pixel interpolation is requested for EXIF axis maps.

## Important limits that remain OPEN

- Windows real WinRT BitmapDecoder EXIF decode / raster PDF reopen / interactive GUI visual QA is **NOT VERIFIED** by a framework-independent coordinate unit test.
- Physical Android JPEG EXIF 2..8 bitmap colors, corners, preview crop handles, PdfRenderer output, PDF rendered pixel comparison and Android SAF overwrite/error preservation **NOT VERIFIED**. On-device Android memory headroom is preflight estimate, not physical proof.
- PNG eXIf orientation compatibility is **NOT VERIFIED**; this first adapter implements **JPEG only**. PNG without eXIf remains unchanged. Do not claim full PNG EXIF parity, physical Android-Windows parity or release readiness.
- Android PARTIAL dependency/NOTICE inventory FAILURE; 42 parent/child POM rights, SBOM/NOTICE, Windows SDK REDIST, actual WinRT PDF runtime BLOCKED/NOT VERIFIED. Remaining CameraX, OCR/searchable PDF, QR/TLS secure pairing, undo/redo, Android SAF atomic copy, visual QA gates remain open.
- RELEASE NO-GO. No root LICENSE, no main, no private, no merge/force.

## Evidence gate

Only exact final SHA Windows actual .NET source test, WinUI3 native XAML/C# compile, Android Kotlin Compose debug compile/lint, executed JUnit and eventual GitHub job/step logs count as PASS. The shared TSV proves integer coordinate parity, not image decoder pixel parity; it is intentionally labelled a contract test. Follow with synthetic EXIF-tagged JPEG images and cross-OS actual rendered PDF pixel checks in real device runners.
