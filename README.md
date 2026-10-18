# Embasic E-Scanner — Public Build

This repository is an **independent, zero-private-history CI and build workspace**. Canonical engineering source remains in the separate **private** `ftmstr/Embasic-E-Scanner` repository. No private history, documents, certificates, production image samples, signing keys, credentials, or real user data may be published here.

## Target product stacks
- Windows: **C# / .NET 10 LTS, WinUI 3 / Windows App SDK** (WPF is not the approved target).
- Android: **Kotlin, Jetpack Compose, Material 3, CameraX**.
- The legacy Kotlin Compose Desktop prototype is migration evidence, **not** the Windows target.

## Build boundaries
`windows/` contains the independently built Windows application and contract checks. `android/` contains the Kotlin Android application. `docs/` holds public architecture and security notes. `tests/` holds only synthetic/golden fixtures. `.github/workflows/` contains separate, least-privilege CI jobs.

## Security
**No automatic synchronization from private to public.** Before any source snapshot import: explicit allowlist, complete content/secret and license inspection, dependency/transitive audit, clean authorship and provenance, and independent approval. Use only generated synthetic fixtures. Never use private signing assets in CI.

## Status
**Foundation bootstrap only.** Camera, pairing, OCR, perspective correction, searchable PDF, secure transfer and signed releases are **NOT VERIFIED** here. GitHub Actions checks must actually finish before a PASS can be reported.
