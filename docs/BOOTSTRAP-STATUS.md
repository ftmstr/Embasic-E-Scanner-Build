# Bootstrap status — PUBLIC source-of-truth (2026-10-29)

The PUBLIC repository ftmstr/Embasic-E-Scanner-Build is the **sole active**
engineering repository. PRIVATE ftmstr/Embasic-E-Scanner is inactive. Never
read/sync its source history, protected records, signing keys or binaries
into the PUBLIC repository. No force push, automatic merge, or history rewrite.

**Windows:** .NET 10 C# contracts, SHA-256 bootstrap, and 24 synthetic
contract/PDF fixture assertions have real Windows runner evidence. The
standalone probe is **not** a WinUI 3 scanner, production PDF generator,
OCR provider, or parity release.

**Android:** independently authored Kotlin/AGP foundation with SDK36,
JDK17, SHA-256-pinned Gradle 8.14.6 distribution and upstream-authenticated
wrapper JAR/scripts now exists. The Gradle wrapper source commit,
upstream Apache-2.0 license and exact SHA-256 provenance are preserved in
`docs/GRADLE-WRAPPER-PROVENANCE-20261029.md`. A previous PUBLIC CI
actually assembled/linted the unsigned foundation. Real JUnit
`ScanContractTest` and test-only JUnit/Hamcrest licensing boundary are
now part of the active verification workflow; do not claim them PASS
without completed run/job/step/log and nonempty test XML.

**Still blocking:** root product LICENSE decision (rights holder), full
direct/transitive licensing/SBOM and complete NOTICE, Android/WinUI user
feature parity, device smoke, secure QR/TLS pairing, immutable originals,
offline OCR, staged-validated-atomic PDF and signed release packaging.
Those are roadmap requirements, not achievements of this bootstrap.
`THIRD-PARTY-NOTICES.md` is a **partial** record only.

**Release:** NO-GO; do not equate a verified wrapper or successful
foundation build with commercial product readiness.
