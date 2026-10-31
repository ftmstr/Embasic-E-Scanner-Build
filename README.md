# Embasic E-Scanner — Public Build

This **PUBLIC** repository is the sole active engineering source of truth for future E-Scanner development, verification and releases. The previous private repository is inactive and must not receive new commits or be automatically synchronized here. Its feature claims and test results do not count as verified PUBLIC implementation. No private Git history, documents, certificates, production image samples, signing keys, credentials, or real user data may be published here.

## Target product stacks
- Windows: **C# / .NET 10 LTS, WinUI 3 / Windows App SDK** (WPF is not the approved target).
- Android: **Kotlin, Jetpack Compose, Material 3, CameraX**.
- The legacy Kotlin Compose Desktop prototype is migration evidence, **not** the Windows target.

## Build boundaries
`windows/` currently contains C#/.NET 10 foundation contracts, a bootstrap probe and synthetic PDF self-tests; it is **not yet a complete WinUI 3 scanner**. `android/` contains the Android foundation and remains subject to approved dependency/toolchain verification. `docs/` holds public architecture and security notes. `tests/` holds only synthetic/golden fixtures. `.github/workflows/` contains separate, least-privilege CI jobs.

## Security
**No automatic synchronization from private to public.** Before any source snapshot import: explicit allowlist, complete content/secret and license inspection, dependency/transitive audit, clean authorship and provenance, and independent approval. Use only generated synthetic fixtures. Never use private signing assets in CI.

## Status
**Foundation bootstrap only.** Camera, pairing, OCR, perspective correction, searchable PDF, secure transfer and signed releases are **NOT VERIFIED** here. GitHub Actions checks must actually finish before a PASS can be reported.
