# PUBLIC dependency provenance / parity gates — 31 October 2026

**Scope:** ONLY PUBLIC `ftmstr/Embasic-E-Scanner-Build`. Historical PRIVATE
implementations, test claims and binaries are **not** accepted as PUBLIC
evidence. This is an audit plan and partial source backed inventory, not a
full SBOM, legal review, signed release or feature-complete announcement.

## Android Gradle source and actual resolved-graph evidence

- Source pins AGP 8.13.2, Kotlin Android plugin 2.3.21, Gradle 8.14.6
  distribution with upstream verified wrapper/JAR checksum, JDK 17, SDK 36.
- Prior accepted resolved `:app` debug graph: Kotlin stdlib 2.3.21,
  JetBrains annotations 13.0; JVM unit-test graph additionally includes
  test-only JUnit 4.13.2 EPL-1.0 and Hamcrest Core 1.3 BSD.
- Public CI verifies two scopes, hashes locally cached selected Maven JAR
  bytes and captures both root and `:app:buildEnvironment` plugin graphs.
  Source metadata, local cache hash and selected Maven coordinate are
  **three distinct pieces of evidence** and NONE alone proves official
  upstream binary provenance or licensing rights.
- Actual initial `buildEnvironment` CI run 41179529687 job 124473900817
  reported SHA-256 `9f2b88781ebd4e51c3ea1406daad8b2706287f3b35f6d8b7550dbfb917c7b389`
  of a 29,509 byte report and 174 raw Maven coordinate *candidates*.
  This is NOT 174 deduplicated resolved components; requested and selected
  versions and project scopes require independent parsing, which is now
  tested in PUBLIC `audit_gradle_plugin_graph.py`. Verify its next CI
  job before declaring its parser PASS.
- The partial THIRD-PARTY-NOTICES uses Maven publisher POM metadata only.
  Android SDK Terms, AGP/Kotlin plugin transitives, wrapper license, AGP
  embedded tool binaries, release variant, byte-level JAR origins and the
  full dependency LICENSES/SBOM are still OPEN.

## Windows .NET 10 foundation dependencies

PUBLIC project files:

1. `windows/Embasic.EScanner.Contracts/Embasic.EScanner.Contracts.csproj`
2. `windows/Embasic.EScanner.SelfTest/Embasic.EScanner.SelfTest.csproj`
3. `windows/Embasic.EScanner.Bootstrap/Embasic.EScanner.Bootstrap.csproj`

They target `net10.0`, not `net10.0-windows...`. Direct project
references are inside PUBLIC and no external PackageReference exists.
A separate audit now reads each *actual* `obj/project.assets.json`
after Windows CI has run the .NET build. It rejects an unreviewed external
NuGet package, MSBuild import or changed target framework. This is stronger
than source-only PackageReference inspection, but **does not** audit .NET SDK
ref packs, nuget.config feeds, Windows App SDK, Windows SDK or signed binaries.

Windows bootstrap run 41179624122, job 124474170879: 7/7 synthetic
dependency audit tests PASSED and actual restore inventory reported
`externalNuGetPackageCount=0` across the three foundation projects.
Restore assets SHA-256 hashes were included in its log. This is not a
WinUI 3 UI build or Windows runtime smoke test.

## Native WinUI 3 blocker — independent from .NET console foundation

Microsoft's official platform guidance distinguishes:

- **Windows SDK:** native Windows headers, APIs and WinRT metadata;
- **Windows App SDK:** separately shipped NuGet framework containing WinUI 3,
  app lifecycle and windowing; release versions/requirements must be checked;
- **Windows OS/runtime:** the target system and availability of platform APIs;
- **.NET TFM:** WinUI 3 desktop projects require a Windows-specific target,
  suitable Windows App SDK NuGet dependency, manifest, packaging/runtime
  and compatible toolchain. The current PUBLIC `net10.0` console projects
  do not provide these.

Official sources:
https://learn.microsoft.com/en-us/windows/apps/get-started/versioning-overview
https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/support
https://learn.microsoft.com/en-us/windows/apps/whats-new/whats-new-for-developers

**NO Windows App SDK version has been added/pinned** here. Do not assume
the newest catalog listing is a verified compatible, licensed, secure
runtime for the product; confirm stable channel, SDK version, .NET 10
toolchain compatibility, transitive notices and device smoke before add.

## Release/privacy/feature parity blockers

- Owner-approved PUBLIC product root LICENSE absent. Third-party notices
  are partial only. A PUBLIC repository is not a commercial license grant.
- Windows and Android must each independently complete native capture/import,
  auto/manual crop, perspective, enhancement, workspace selection/reorder,
  undo/redo, offline OCR, searchable PDF, PDF/JPEG/PNG atomic export.
- Android QR/TLS certificate fingerprint pinning, short-lived nonce,
  replay protection, HTTPS/WSS full-resolution transfer into Windows
  ScanSession still require implementation, golden tests and device smoke.
- Immutable originals, restart recovery, low storage, cancelled transfer,
  1/20/100/500/1000-page performance and production privacy/ad SDK boundaries
  have NO accepted PUBLIC release evidence.

**Gate decision:** PR #1 remains OPEN; `main` untouched; NO-GO for v1.0.
Do not auto-generate the rights-holder root LICENSE or import PRIVATE assets.
