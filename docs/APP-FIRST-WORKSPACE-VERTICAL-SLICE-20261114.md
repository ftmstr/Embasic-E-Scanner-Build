# Embasic E-Scanner — first usable app vertical slice (PUBLIC, 2026-11-14)

**Project status: implementation preview, NOT production-ready. RELEASE NO-GO.**

## Why the work moved

PUBLIC `README.md` and `docs/ARCHITECTURE.md` explicitly warned that the
prior Windows C# contracts and Android Kotlin foundation had **no actual
native scanner UI**. The user prioritized working applications over repeated
synthetic security-only turns. Canonical starting branch:
`fix/pdf-fixture-selftest-20261018`, Draft PR #1,
`40f3dc5c4ca0edf814fe84e711e29f5313763017`, with no later HEAD,
six green CI workflows, 75/75 steps and 26/26 Android host-JVM JUnit cases.
The matching last Drive report was checked in
`Uygulama/Embasic E-Scanner/Raporlar`.

## Android Kotlin / Compose / Material 3

The formerly static `MainActivity` is now a real Compose screen with:
- SAF multi-select of PNG/JPEG via `ACTION_OPEN_DOCUMENT` without broad storage
  permission; no network, ad SDK or camera permission
- boundary-checked files (64MiB), PNG/JPEG signature detection, SHA-256
  hashing, private GUID-named original assets with same-directory atomic
  stage-to-original move, and manifest reload with SHA-256 revalidation
- asynchronously generated bounded thumbnails, multi-page lazy list, move
  up/down and deletion, local workspace order persistence
- native Android `PdfDocument` export to A4 raster pages, private staging
  with `fsync`, reopening via `PdfRenderer` to verify page count, then
  copying to a newly user-picked SAF destination using `ACTION_CREATE_DOCUMENT`.
  The final SAF destination copy **is not atomic**; on failure a partial
  user-selected destination document could remain. This is explicitly
  indicated in the UI. There is no OCR/text layer or recipe-based cropping.

Android build inputs: AGP 8.13.2, Kotlin 2.3.21, SDK36,
Compose compiler plugin `2.3.21`, BOM `2025.08.00`, UI/Foundation/
Material3. BOM `2026.09.00` was initially tested but its dependencies
required compileSdk37/AGP9.1 and produced a real `checkDebugAarMetadata`
failure; the toolchain was deliberately preserved and the BOM pinned back
to a compatible vintage. The **unsigned Android clean-room compile/lint
workflow** must be independently checked; this is NOT on-device smoke.
The new Compose compiler and UI runtime bring unreviewed transitive
dependencies. Previously pinned plugin snapshot/NOTICE counters were
built for the older 147-module graph, and the Android Foundation
audit legitimately raises a stale partial inventory blocker with the new
graph (observed 149 modules). Do not bypass or reclassify the legal gate.
Product dependency-license inventory, notice texts, SBOM and SDK
distribution rights remain **NOT VERIFIED**.

## Windows .NET10 / WinUI3

A new independent native WinUI3 app under
`windows/Embasic.EScanner.Desktop/` targets Windows App SDK **2.6.4**
(`WindowsPackageType=None`, unpackaged, framework-dependent, x64).
It has a real XAML window, Windows file picker, JPEG/PNG byte-signature
check, 64MiB bounded copy to generated-name private originals,
SHA-256 workspace manifest restore, native thumbnail cards,
move up/down and delete, and a PDF save action.

A first real **raster** A4 PDF source implementation uses the OS
`Windows.Graphics.Imaging.BitmapDecoder` with RGBA-to-RGB conversion,
`ZLibStream`-compressed PDF image XObjects, a page tree and xref table.
It stages into the **selected destination's own directory**, reopens with
`Windows.Data.Pdf.PdfDocument` to validate page count and then uses a
same-directory atomic replace. It deliberately does **not** perform OCR,
perspective correction, color management, filters or a searchable PDF.
24-megapixel decoded-pixel and 512MiB output limits are initial
safeguards; native runtime/PDF reopen must still be exercised physically.

The new PUBLIC Windows workflow
`.github/workflows/windows-winui-preview.yml` compiles the actual
unpackaged WinUI3/XAML app on a real `windows-latest` runner. It is
**not** evidence of window launching, visual UX, an installer, SDK
redistribution rights or commercial shipping. WinAppSDK/BuildTools
license and REDIST/EULA gates remain unresolved.

## Outstanding acceptance and immediate roadmap

**NOT RUN/NOT VERIFIED**: Android physical device app launch and actual
photo/PDF picker use; Windows WinUI3 actual GUI launch and exported PDF
opening on user machine; Windows/Android feature parity; camera capture;
automatic/manual crop, perspective correction, rotate and enhancements;
offline OCR/searchable PDF; QR/WSS pairing; fully atomic Android SAF final
output; full native 500/1000-photo UI tests; signed installers, SBOM/NOTICE
and rollback.

Next vertical slices:
1. Physical Android/Windows smoke on supported devices; collect observed
   screenshots and verify actual output PDF rendering and order.
2. Non-destructive TransformRecipe crop/perspective/filter UI on **both**.
3. OCR/searchable PDF and page workspace parity.
4. Safe same-WiFi QR/TLS pairing and releases only after legal gates.

**Important scope:** coding and CI build of a UI are milestones, but **not
production-ready** or general native feature acceptance. No changes to
PRIVATE repo, main branch, merge state, force push or root LICENSE.
