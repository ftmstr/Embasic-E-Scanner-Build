# PUBLIC Maven parent POM metadata triage — SHA evidence, not licence rights (9 Nov 2026)

**Decision: 42/42 child POM licensing review items remain OPEN. Product release NO-GO.**

## Why this matters

The previously verified PUBLIC Android Gradle root/app buildEnvironment
partial inventory selected 147 Maven plugin/build-tool modules. 42 selected
child POMs do not contain direct licence names (12 POM_NOT_CACHED and 30
POM_WITHOUT_DIRECT_LICENSE_NAME); 105 direct POM names are themselves still
unreviewed supplier claims. The cache recorded **59 ancestor evidence rows**
for missing-direct-license children. Of these, several parent POMs contain
complex/multiple licence name declarations. Those were not visible in the
previous flat 42-row legal review queue.

The latest before-this-change CI log:
https://github.com/ftmstr/Embasic-E-Scanner-Build/actions/runs/42544364627

Among the explicitly UNVERIFIED cached parent *supplier metadata* were:

| Selected child Maven purl | Parent coordinate / cached POM SHA256 | Supplier-declared parent licence names |
| --- | --- | --- |
| pkg:maven/com.sun.activation/javax.activation@1.2.0 | com.sun.activation:all:1.2.0 / 1d8518e3ac7532a104e4f7be77def37c982e530723c6bdb3d67708cce2b0c2c4 | CDDL/GPLv2+CE |
| pkg:maven/com.sun.istack/istack-commons-runtime@3.0.8 | com.sun.istack:istack-commons:3.0.8 / a0f0517e8512f0fbcc7b8295c12f6566a3d0c2d86d655639dc662ef8c0c7ebe5 | Eclipse Distribution License - v 1.0 |
| pkg:maven/com.sun.xml.fastinfoset/FastInfoset@1.2.16 | org.eclipse.ee4j:project:1.0.5 / 916b4794d8d8220a59a3fdf6a64dbe794aeb23395e888b81ae36a9b5a2c591a6 | Eclipse Public License v. 2.0; GNU General Public License, version 2 with GNU Classpath Exception |
| pkg:maven/jakarta.activation/jakarta.activation-api@1.2.1 | com.sun.activation:all:1.2.1 / 360883bf64486ecef161b8f282f6503536dd1a670d53a0a871c8fb20170e6795 | EDL 1.0 |
| pkg:maven/jakarta.xml.bind/jakarta.xml.bind-api@2.3.2 | jakarta.xml.bind:jakarta.xml.bind-api-parent:2.3.2 / 15a55b7d537c9f9970aead28d2af97c059f65ff6102f76bbd29f1247dd8a6dfb | Eclipse Distribution License - v 1.0 |

These are **parent POM metadata names**, not verified effective child licensing,
actual exact licence texts, signed upstream provenance, granted redistribution
rights or proof that these packages ship in an APK. The exact POM SHA256 values
identify only locally cached bytes, not independently authenticated upstream
bytes. There is no assertion that an Eclipse, GPL, CDDL or EDL obligation
actually applies to the shipped E-Scanner product. Independent review must
decide parent inheritance, dual licensing, chosen option, exceptions, test/
build-tool versus linked runtime boundary, copyright/NOTICE and release payload.

## New fail-closed mechanism

The existing scripts/reconcile_gradle_pom_license_gaps.py now captures
**every** cached parent evidence chain for all 42 selected child POM gaps:

- exact parent coordinate, local POM SHA256 or explicit missing state;
- verbatim-ish sorted supplier licence NAME hints (bounded, not full text);
- explicit attention signals for names matching possible GNU GPL/LGPL/AGPL,
  Eclipse Public/Distribution, CDDL, Mozilla/MPL or Classpath terms;
- per-row text-only reviewer priority, never automatic effective POM inheritance.

The checker rejects cached parent licence names without a 64-hex SHA,
a missing/too-deep parent that tries to claim a licence, unsafe POM coordinates,
duplicate/cyclic parent chain, unbounded names and forged approval.
The new attention marker is a search aid, **not a policy determination**:
the same output still says licenceApproved=false, releaseApproved=false,
parentLicenseInheritanceVerified=false, rights NOT VERIFIED.

The existing tests/test_reconcile_gradle_pom_license_gaps.py synthetic
regressions cover complex dual-license metadata, GPLv2+CE, LGPL,
EClassPath descriptions, valid permissive names without approval, missing
parent SHA, malformed/duplicate parent chains, forged parent claims and
complete 42 selected POM gap preservation.

CI reads the newly generated gradle-pom-legal-review-queue.json and requires
the parent metadata evidence to remain bounded, with no implied rights; the
JSON is uploaded as scoped dependency evidence, **not an SPDX/CycloneDX SBOM**.

## Microsoft exact BuildTools licence remains a separate gate

The Windows-specific disposable NuGet restore selected
Microsoft.Windows.SDK.BuildTools 10.0.26100.4654. The official
https://www.nuget.org/packages/Microsoft.Windows.SDK.BuildTools/10.0.26100.4654
calls it build tools; Microsoft
https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads
lists the exact SDK edition release. A build-tool NuGet package,
its legacy WinSDKLicenseURL pointer, a valid raw/neutral SHA512, and
an in-package REDIST filename candidate count of zero do NOT establish
per-file commercial redistributable rights for E-Scanner.
The EWDK license
https://learn.microsoft.com/en-us/legal/windows-sdk/license-terms-ewdk
has REDIST restrictions but is not a version-and-package-specific grant here.

**BLOCKED**: exact EULA / authoritative REDIST list, actual installer
composition, owner-approved root product LICENSE, full third-party notices
and SPDX/CycloneDX inventory, complete native Android/Windows parity,
signed installers/APK and runtime smoke. Native 0/41, platform foundation
3/6, structural 4/5, release 0/8 remain unchanged until independent proof.

Only PUBLIC branch fix/pdf-fixture-selftest-20261018; PR #1 OPEN/DRAFT.
PRIVATE/main/merge/force are out of scope.
