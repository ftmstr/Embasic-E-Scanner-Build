# PUBLIC Windows WinUI 3 / Windows App SDK release-candidate preflight — 2 Nov 2026

This is **source-backed candidate research**, NOT a dependency installation,
LICENSE grant, restored NuGet transitive graph, Windows native GUI build or
release approval. The PRIVATE repository remains out of scope.

## Official channel and compatibility evidence

- Microsoft release-channel page currently lists **Windows App SDK 2.6.4**
  as the Stable channel release dated **27 October 2026** (not Preview,
  Experimental or an unverified catalog pin).
  https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/release-channels
- Official 2.0 family release notes confirm 2.6.4 servicing fixes and
  an ONNX Runtime update. This means the full Windows App SDK graph is
  broader than a WinUI XAML package alone, and all transitive binaries,
  licenses, privacy and maintenance must be reviewed before including it.
  https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/release-notes/windows-app-sdk-2-0
- Official Windows App SDK compatibility table identifies Windows 10 version
  1809 (OS build 17763) as an SDK-level minimum; application APIs may need
  stricter per-API runtime guards and project-specific minimum OS settings.
  https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/support
- Microsoft's .NET 10 WinUI 3 getting-started guide offers a Windows-specific
  TFM example such as `net10.0-windows10.0.26100.0` and requires Windows
  SDK, developer-mode and matching tools. **This is an option to validate,
  not an approved E-Scanner target**.
  https://learn.microsoft.com/en-us/windows/apps/get-started/start-here
- The official Windows App SDK NuGet 2.6.4 publisher listing is available.
  The separate WinUI package lists **computed net10.0-windows compatibility**,
  but that does NOT prove actual CI restore, deployment or license closure.
  https://www.nuget.org/packages/Microsoft.WindowsAppSDK/2.6.4
  https://www.nuget.org/packages/Microsoft.WindowsAppSDK.WinUI/2.6.4
- NuGet WinUI 2.6.4 metadata lists transitive requirements including
  `Microsoft.Web.WebView2 >= 1.0.3719.77`,
  `Microsoft.WindowsAppSDK.Base >= 2.6.4`,
  `Microsoft.WindowsAppSDK.Foundation >= 2.6.4`, and
  `Microsoft.WindowsAppSDK.InteractiveExperiences >= 2.6.4`.
  This is publisher **metadata only**. Exact versions and additional
  transitive dependencies must be captured by a real Windows restore.

## PUBLIC vs proposed Windows scope

The three existing PUBLIC projects `Embasic.EScanner.Contracts`,
`Embasic.EScanner.SelfTest`, and `Embasic.EScanner.Bootstrap` target
`net10.0` and are .NET Foundation/console tests, not WinUI3 GUI.
Current Windows CI audits their actual restore assets and rejects unexpected
external packages. The current known external NuGet count is **zero** for
these three projects; it does **not** apply to future WinUI dependencies.

Before adding `Microsoft.WindowsAppSDK` into PUBLIC user-facing code:

1. Obtain an owner-approved root PUBLIC product LICENSE (currently absent).
2. Download the exact Stable NuGet in a disposable, separately audited
   Windows toolchain, verify package hashes and publisher/metadata provenance.
3. Capture all resolved direct/transitive NuGet packages, exact versions,
   package licenses, notice requirements, terms, and release SBOM evidence.
4. Verify an isolated Windows-specific .NET 10 target + matching SDK,
   native WinUI 3 XAML compilation, runtime, OS minimum and x64 smoke.
5. Confirm local-only scanning and no image/OCR/pairing secret leakage to
   WebView2/Windows ML/diagnostics or other SDK components.
6. Then make an explicit reviewed and reproducible SDK pin; no blind
   `dotnet add package`, SDK import, root LICENSE creation or PR #1 merge.

**Decision:** candidate Stable family known; exact WinUI runtime integration
and SDK/NuGet licensing remain **BLOCKED/NOT VERIFIED**. RELEASE NO-GO.
