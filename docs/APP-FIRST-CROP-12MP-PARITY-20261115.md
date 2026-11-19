# APP-FIRST 12MP CROP OUTPUT PARITY — 2026-11-15

Scope: PUBLIC Android Compose PdfDocument + Windows WinUI3 RasterPdfWriter, using the existing manual quad, rotation and workspace. No new package, no UI rewrite, no private assets. Signed product **RELEASE NO-GO**.

## Prior contract and measurable change

Before: original-space draggable normalized quadrilateral, persist/reset and rotate; both crop render paths forcibly downscaled to **2400 pixels maximum edge**, 6MP crop result, even when a synthetic 4000×3000 original could preserve more document detail.

Now: **CropOutputPlan** is framework-independent Kotlin/C# source, with one canonical synthetic **tests/golden/perspective-output-v1.tsv** read by Android JUnit resources and Windows .NET RotationSelfTest. Both derive four-quad edge lengths in source pixel coordinates, explicit positive half-up rounding, no upscale factor beyond 1 (except legacy minimum 32px for tiny fixtures), **6000 pixels/edge and 12,000,000 pixels maximum output**. For 4000×3000 inset crop, output is **3360×2520** (not old <=2400-edge); for 6000×4000 inset, planned output 4243×2828 (not 5040×3360). No template fixture is a real user document.

Android export-only decode no longer calls thumbnail-scale decodeBounded(...,2400). Eligible input <=24MP / <=8000px source edge decodes at original pixel dimensions, with a preallocation process-heap estimate (decoded ARGB + warped output + 24MiB margin); failure is explicit, not a silent 2400px preview downgrade. Input >24MP may be power-of-two sampled as before; this path is not claimed full resolution or identical to Windows, whose decoder rejects source >24MP. Android input geometry >100MP is rejected. Source original SHA256 is checked before decode; only output bitmap is transformed. Android EXIF handling and device-specific memory behavior remain subject to physical QA.

Windows WinRT decoder still limits 24MP input; pure CPU bilinear reverse homography now uses the same measured 12MP output size. The prior same-directory staged+reopen+replace logic remains; actual WinRT PDF save/reopen and visual content **NOT VERIFIED** on physical Windows. Windows isolated compile is not a runtime acceptance.

## Test contract / limitations

Five golden cases: 12MP portrait/landscape inset, 24MP bounded inset, 12MP skewed quadrilateral, 5000×3500 narrow receipt. Four invalid original dimensions are fail-closed test cases. The same TSV is included as a resource in Android JUnit and copied to the Windows .NET test output. Windows additionally executes a synthetic 8×8 RGB warp; there is no independent Android Skia-vs-Windows pixel color parity yet. Test gate: **real exact HEAD native compile + executed JUnit + .NET selftest**; do not infer a physical GUI acceptance.

Remaining P0: Android real-device manual handles+SAF loss/partial-write, EXIF normalization, PDF rendered pixel comparison; Windows real WinUI3 UI launch and WinRT PDF raster output on physical interactive session; 100/500-page perf and low memory; tile-based true high-res >12MP, OCR/searchable PDF, secure QR/TLS pairing. Android partial Gradle NOTICE/license audit, 42 child-POM rights, Windows SDK REDIST/EULA, SBOM/NOTICE, signing/rollback **BLOCKED**. No release pass inferred from a compile.
