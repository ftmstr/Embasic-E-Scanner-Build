# PUBLIC selected Gradle POM licence gap reconciliation — 9 Nov 2026

Status: **LEGAL REVIEW QUEUE ONLY — RELEASE NO-GO.**

## Evidence boundaries

Source of selected components is the actual Android Gradle root/app
buildEnvironment cache inventory, NOT an invented package list. PUBLIC runner
observed 147 selected plugin/build-tool Maven modules; 105 contained a direct
supplier POM licence name, while **42 selected child modules lacked direct
licence metadata**: 12 POM_NOT_CACHED, 30
POM_WITHOUT_DIRECT_LICENSE_NAME, 0 UNREADABLE_POM. These numbers do not
mean that 105 licences were reviewed or that 42 artefacts are unlicensed.

Separate research of selected missing child POMs and missing ancestor POMs
uses allowlisted exact Maven Central / Google Maven HTTPS paths, bounded
requests and SHA-256 of downloaded metadata. A supplier licence NAME,
parent reference, URL, downloaded bytes or a POM hash is **never** a legal
rights determination. Historical and future counts must come from a
successful job's evidence, not this document.

The new offline-only reconciliation
scripts/reconcile_gradle_pom_license_gaps.py joins the two previously
retained PUBLIC CI reports (gradle-plugin-artifact-evidence.json and
gradle-missing-pom-source-research.json). It checks **every** selected
child, every missing direct POM row, parent hint and every bounded remote
POM research target. It refuses spoofed release approval, fake publisher
attestation, dropped/duplicated gaps, changed versions, unallowlisted
research URLs, missing SHA, reclassified parent terms and inconsistent
counts. The result gradle-pom-legal-review-queue.json is a stable
42-item **unresolved legal worklist** with source-research status and
next-review action, NOT a closure of the selected graph.

No automatic child licence inheritance from a cached/remote parent is
performed. No POM licence text is independently adjudicated by the
script. Even if remote source metadata includes an Apache-2.0/MIT/BSD
name, the relevant exact licence, notices, component scope, copyright,
transitive dependencies and actual release bytes still require review.

## Distinct Microsoft Windows SDK BuildTools blocker

The separately audited disposable .NET 10 Windows App SDK 2.6.4 restore
selected Microsoft.Windows.SDK.BuildTools **10.0.26100.4654**. The
NuGet package has no direct nuspec licence declaration; it points to
https://aka.ms/WinSDKLicenseURL. Its raw archive/cache SHA-512 and
signature-neutral NuGet restore/content SHA-512 matched separately.
These integrity checks do not attest the publisher's signature or grant
SDK redistribution rights. In-package REDIST filename candidates = 0
does not establish that an applicable SDK REDIST list does not exist.

Official version-matched references:
- https://www.nuget.org/packages/Microsoft.Windows.SDK.BuildTools/10.0.26100.4654
  labels the exact item as *build tools*, explicitly without supported
  framework assets; supplier NuGet metadata is not a signed licence.
- https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads
  lists the Windows SDK 10.0.26100.4654 installer and ISO (July 2025).
  It does not itself publish the exact product redistributable file list.
- https://learn.microsoft.com/en-us/legal/windows-sdk/license-terms-ewdk
  concerns an Enterprise Windows Driver Kit and cannot be applied as an
  automatic licence for this NuGet package or a Windows 11 SDK installer.

**Disposition:** exact version-applicable licensing instrument, legal
terms applicable to build-only use and any REDIST.TXT / distributables
list + release-payload per-file review remain NOT VERIFIED. The E-Scanner
Windows installer does not exist yet. A binary package with a matching
digest is not permission to ship the build tools. Do not add a product
root LICENSE without the rights-holder's explicit choice and approval.

## Test and release gates

New synthetic tests test_reconcile_gradle_pom_license_gaps.py deliberately
spoof remote metadata, wrong PURL/version, truncated graphs, parent
inheritance and elevated legal approval. Android CI runs them after
the previous HTTP source research and rejects any missing 42-queue item,
changed source gap distribution or falsely upgraded legal status.
The retained JSON artifact helps a human work through each gap.
Technical CI PASS is NOT a commercial release grant.

Outstanding: 42 component-by-component exact text and parent/transitive
licence reviews; BuildTools version-specific REDIST; complete NOTICE and
THIRD-PARTY LICENSES; owner-approved product LICENSE; full SPDX/CycloneDX;
native Android/Windows scan, OCR, page integrity, secure QR capture,
performance/device parity, signing and rollback. Native 0/41, platform
foundation 3/6, structural 4/5, release 0/8 until real evidence changes.

No PRIVATE/main/merge/force operations are part of this review.
