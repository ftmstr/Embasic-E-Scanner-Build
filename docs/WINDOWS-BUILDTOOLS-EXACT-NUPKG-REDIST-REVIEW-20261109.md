# PUBLIC Windows SDK BuildTools 10.0.26100.4654 — exact archive vs REDIST rights (9 Nov 2026)

**Status: RESTORE-ONLY / THIRD-PARTY LEGAL REVIEW BLOCKED / PRODUCT RELEASE NO-GO.**

Repository: PUBLIC ftmstr/Embasic-E-Scanner-Build, branch
fix/pdf-fixture-selftest-20261018; PR #1 stays OPEN/DRAFT.
No PRIVATE source, main, merge, forced update, signing key or product binary
has been involved in this review.

## Why the existing 16-package restore did not settle licensing

A disposable .NET 10 Windows AppSDK 2.6.4 restore observed 16 packages,
with 15 direct nuspec supplier license declarations. The remaining exact
pkg:nuget/microsoft.windows.sdk.buildtools@10.0.26100.4654 has
NO_DIRECT_NUSPEC_LICENSE and the legacy supplier pointer
https://aka.ms/WinSDKLicenseURL. Neither a publisher-supplied license
URL nor a package SHA is an executable distribution right.

Microsoft's exact NuGet page calls the package **build tools required for
building projects targeting the Windows SDK**, with no supported framework
assets. This is not evidence that the contained files can be embedded in or
redistributed with E-Scanner. EWDK licensing examples refer to REDIST.TXT
or an enumerated redistributables list; the identified EWDK terms discuss
Windows 10 / Visual Studio 2017 and are **not automatically applicable to
this exact NuGet 10.0.26100.4654 package**.

Official references and their limitations:
- https://www.nuget.org/packages/Microsoft.Windows.SDK.BuildTools/10.0.26100.4654
  (exact package and version; supplier description, not rights review)
- https://aka.ms/WinSDKLicenseURL
  (legacy supplier pointer; exact applicable terms still need review)
- https://learn.microsoft.com/en-us/legal/windows-sdk/license-terms-ewdk
  (EWDK contextual license; NOT an exact 10.0.26100.4654 licence grant)
- https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/deploy-packaged-apps
  (app packaging guidance, not SDK BuildTools rights)

## New bounded, deterministic source gate

scripts/audit_windows_sdk_buildtools_nupkg.py reads the PUBLIC CI-created
windowsapp-sdk-restore-evidence.json and the disposable restore NuGet cache.
It refuses any alternate BuildTools version, concealed missing-license gap,
publisher/legal escalation, untrusted cache root, package path symlink or
oversized package. For the exact target only, it requires **three-way SHA-512
equality** between resolved project.assets.json supplier digest, NuGet cache
.nupkg.sha512 digest and actual locally downloaded .nupkg bytes. It also
requires ZIP-embedded exact .nuspec SHA-256 to match the extracted
.nuspec whose SHA-256 was measured by the existing restore audit.

ZIP metadata enumeration rejects traversal, absolute/drive-like names,
duplicates and symlinks, bounds entry counts and declared uncompressed
bytes. It only decompresses and hashes the small .nuspec. It lists
REDIST.TXT-like and LICENSE/NOTICE-like filenames as *candidate evidence*
without interpreting or reproducing legal texts. File presence or
non-presence inside this **NuGet package** alone is NOT the authoritative
Microsoft SDK REDIST file list.

Negative tests use generated synthetic bytes and deliberately invalid
SHA, version, ZIP path, symlink and elevated licence assertions. CI publishes
windows-sdk-buildtools-26100-4654-archive-evidence.json alongside the
existing temporary NuGet restore evidence. A passing archive hash gate
does not make the Windows user-facing app build, instantiate WinUI XAML,
or provide publisher signature verification.

**Always remain FALSE**: exactVersionLicenseTermsVerified,
redistributionFileListVerified, redistributableAssetRightsVerified,
publisherSignatureVerified, archiveSignatureVerified,
windowsNativePackageVerified, sbomComplete, releaseApproved.
noticeClosure=NOT_VERIFIED. An unexpected package/checksum is a real
fail-closed technical error, not a license denial determination.

## Release owner/licensing queue

1. Establish the *actual, version-applicable* Microsoft rights instrument
   for this specific SDK BuildTools NuGet package; preserve source/date and
   assess developer build-use vs redistribution.
2. Identify the authoritative exact SDK REDIST.TXT or listed file rights.
   Cross-check **each shipped file** in the **actual Windows installer**
   against that list and its restrictions. No installer exists yet.
3. Retain complete exact license texts and third-party notices as required,
   and obtain rights-holder approval for the PUBLIC product root LICENSE.
4. Complete 42 unresolved Android Gradle direct POM license gaps (12
   not-cached POMs, 30 no-direct-license-name POMs), parent/transitive
   notices, Windows/Android runtime graphs, SPDX/CycloneDX SBOM.
5. Independently validate native Android/Windows scan, immutable original,
   transformations/workspace, OCR/searchable PDF, atomic staged export,
   HTTPS/WSS QR TLS fingerprint pinning and replay resistance, golden/device
   parity, signing, rollback and privacy.

No redistribution rights, product release, native test PASS or feature
acceptance should be inferred from a green NuGet archive evidence gate.
