# Embasic E-Scanner — Public Build

This **PUBLIC** repository is the sole active engineering source of truth for future E-Scanner development, verification and releases. The previous private repository is inactive and must not receive new commits or be automatically synchronized here. Its feature claims and test results do not count as verified PUBLIC implementation. No private Git history, documents, certificates, production image samples, signing keys, credentials, or real user data may be published here.

## Target product stacks
- Windows: **C# / .NET 10 LTS, WinUI 3 / Windows App SDK** (WPF is not the approved target).
- Android: **Kotlin, Jetpack Compose, Material 3, CameraX**.
- The legacy Kotlin Compose Desktop prototype is migration evidence, **not** the Windows target.

## Build boundaries
`windows/` now contains C#/.NET 10 foundation contracts **and an actual WinUI 3 preview project** with local image import, thumbnail ordering and a first raster PDF export code path. `android/` now contains the Kotlin/Compose/Material 3 preview with multi-image import, private originals, thumbnail ordering and Android platform PDF export. Both preview projects are **not feature-complete** and remain subject to toolchain, transitive dependency rights and device verification. `docs/` holds public architecture and security notes. `tests/` holds only synthetic/golden fixtures. `.github/workflows/` contains separate, least-privilege CI jobs.

## Security
**No automatic synchronization from private to public.** Before any source snapshot import: explicit allowlist, complete content/secret and license inspection, dependency/transitive audit, clean authorship and provenance, and independent approval. Use only generated synthetic fixtures. Never use private signing assets in CI.

## Status
**First functional UI source, NOT release.** Android Compose and Windows WinUI3 workspace previews have been added. Builds, source-level PDF implementations and simulated fixtures are not evidence of actual device/GUI operation. Image capture from a camera, perspective correction, offline OCR, searchable PDF, secure QR/TLS transfer, full Android-Windows parity, atomic Android SAF final output, SBOM/licensing and signed releases remain **NOT VERIFIED** or unimplemented. Only completed exact-HEAD jobs may be reported PASS.
