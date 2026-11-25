# PUBLIC E-Scanner — first visible non-destructive rotation on Android + Windows

Date: 2026-11-14 (Europe/Istanbul). Repository **PUBLIC** `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, PR #1 OPEN/DRAFT/unmerged. **RELEASE NO-GO.** No PRIVATE, `main`, merge, force push, or root LICENSE operation.

## Canonical input and product direction

Starting HEAD `dc4b061589df8d59c299021513e8d45982d6096f` matched branch/PR exactly (0 ahead/behind). Seven actual starting GitHub Actions PR workflows: **6 completed SUCCESS**, **Android Kotlin Foundation FAILED** at the still-unclosed third-party partial licensing inventory. The prior 14-Nov `PUBLIC Uygulama Odaklı Tur: Android Compose ve Windows WinUI3 CI Kabul Engelleri` native Google Doc `1FuDic5m8qhpikU-IK9brHVfQwGNNlfebRnTUb4wCd3k` was read from Drive `Uygulama/Embasic E-Scanner/Raporlar`.

The functional Android Compose/Material3 and Windows C#/.NET10 WinUI3 previews **already** included local PNG/JPEG import, bounded immutable source copies with SHA-256, thumbnail workspace, reordering/removal and platform A4 raster PDF exporters. Do NOT redo this prior work. Do NOT confuse the source UI and native build with an installed physical-device/GUI acceptance.

This turn prioritizes **one self-contained, visible cross-platform vertical slice** over more infrastructure: clockwise 90° / reset, persisted rotation recipe, transformed thumbnail, and oriented raster PDF while retaining the original asset SHA and bytes.

## Functional behavior parity contract — narrowly scoped

| Contract | Android | Windows |
|---|---|---|
| New page angle | `0` | `0` |
| Button | `↻ 90°`, `Sıfırla` | `↻ 90°`, `Sıfırla` |
| Clockwise sequence | 0→90→180→270→0 | 0→90→180→270→0 |
| Immutable source | Original private PNG/JPEG not rewritten | Original private PNG/JPEG not rewritten |
| Thumbnail | Compose `graphicsLayer.rotationZ` | WinUI3 `RotateTransform` about center |
| Persisted recipe | Canonical `filename:sha256:degrees` | Canonical `filename:sha256:degrees` |
| Legacy manifest | Two-column row migrates to 0° | Two-column row migrates to 0° |
| Malformed angle | Reject noncanonical, not silently normalize | Reject noncanonical, not silently normalize |
| Export | `PdfDocument` canvas transform of decoded image | PDF image affine `cm` matrix in stage |
| A4 | Preserve 595×842 page, recompute aspect ratio after orientation | Preserve 595×842 page, recompute aspect ratio after orientation |
| Negative state | No arbitrary angle, crop or perspective claim | Same |

Allowed angles exactly `0`, `90`, `180`, `270` degrees clockwise. Reject strings `45`, `360`, `-90`, `090`, whitespace and nonsensical values. Existing original SHA-256 is retained, not recomputed over rotated thumbnails. Deleting a page is unchanged (deletes its own original) and is not a nondestructive undo operation.

## Exact source changes and contract tests

**Android**: `PageRotationRecipe.kt` stores strict right-angle rules independent of device APIs; `PageRotationRecipeTest.kt` JUnit 4 validates cyclic transitions, reset, two-column migration, all canonical angles, invalid persistence/angle rejection. `MainActivity.kt` adds a per-page clockwise button and reset, applies `graphicsLayer` to the visible thumbnail, persists new angles without touching original bytes, migrates legacy manifest rows, and rotates only the A4 PDF canvas after choosing post-orientation width and height. Final SAF URI copy remains **NON-ATOMIC**, and real Android device `PdfRenderer` output visual QA is NOT VERIFIED. No new Android dependencies or network/advertising modules.

**Windows**: `PageRotationRecipe.cs` implements the same strict cycle/migration and deterministic PDF image affine drawing commands for 0/90/180/270. `MainWindow.xaml.cs` adds actual WinUI3 rotation and reset buttons, thumbnail `RotateTransform`, persisted recipe, and passes `RasterPdfPage(ImagePath,RotationDegrees)` into `RasterPdfWriter.ExportVerifiedPagesAsync`. Existing paths-only PDF API remains for the preexisting PDF smoke test, with an identity recipe. PDF writer validates angle before staging and builds a single correct oriented `cm` matrix per page; original decoded pixels/source file remain unrotated. Separate `windows/Embasic.EScanner.RotationSelfTest` is a **plain net10.0** executable linking the actual rotation class to check all four A4 matrices, migration and rejection. CI runs it without requiring WinRT runtime activation, then builds real WinUI3 XAML/C# and the dedicated PDF smoke project. The latter's actual headless PDF-runtime smoke remains a separately identified BLOCKED/NOT VERIFIED physical GUI acceptance gate.

No manual four-corner coordinate editor, perspective correction, crop or full TransformRecipe history/undo is implemented in this turn. A four-corner UI without validated full-resolution correction would be a fake feature. The next **app-first** vertical slice is normalized four-corner manual editor + full-resolution perspective correction and parity tests on both platforms.

## Actual testing and release gates

Source-build and JUnit/rotation matrix results MUST be read from the **exact final HEAD** GitHub Actions, and final job/step receipts appended to the Drive report. Unfinished runs are **QUEUED / IN_PROGRESS = NOT VERIFIED**, never PASS. CI compile is not a GUI, PDF visual, physical Android device, 500/1000 real scans, signed APK/AAB/Windows package or feature-complete pass.

The 14-Nov Android Foundation licensing audit still has 42 historical direct child-POM/transitive gaps plus new Compose UI/Material3 runtime dependency rights. Root LICENSE rights-holder, Windows App SDK BuildTools EULA/REDIST, NOTICE/LICENSES/SBOM, secure QR CSPRNG and TLS fingerprint pinning, native image pipeline/OCR/searchable PDF, device/GUI smoke and rollback block release. **RELEASE NO-GO**, PR #1 stays Draft.

Next work: verify Android touch and document provider SAF PDF output on a real device; WinUI3 viewport/picker, live PDF export and reopen on an interactive Windows desktop; then manual four-corner crop/perspective, offline OCR and QR/WSS full-res capture. No overall fake progress percentage.
