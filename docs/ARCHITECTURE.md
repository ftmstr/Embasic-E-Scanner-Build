# Public build architecture

Windows C# / .NET 10 LTS / WinUI 3 + stable Windows App SDK, and Android Kotlin / Jetpack Compose / Material 3 / CameraX, are the **approved target stacks**. Legacy Kotlin desktop is not the target Windows application.

Both applications must independently provide image capture/import, immutable originals, non-destructive crop/perspective/rotate/enhance, reorderable multi-page workspace, offline OCR, and staged-validated-atomic PDF export. Those capabilities are roadmap requirements, **not implemented by this bootstrap**.

Cross-language parity uses versioned JSON schemas, stable error codes and synthetic golden fixtures; no framework-specific type enters wire contracts.

Phone-to-PC pairing requires QR payload with version, endpoint, session ID, one-time nonce/token, expiry and certificate SHA-256 fingerprint; HTTPS/WSS, fingerprint pinning, replay protection, strict size/MIME/hash admission, per-page staging and identity isolation. Never trust the local Wi-Fi network or use Bluetooth. Never use IMEI, MAC address or Android ID as identity.

Public source snapshot gate: explicit file allowlist; scrubbed content and metadata, source and transitive licenses, binary provenance, no real customer documents, no secrets, no private Git objects or history. Fail closed and block publication on any uncertainty. Public PR workflows must use read-only GITHUB_TOKEN and no secret access.
