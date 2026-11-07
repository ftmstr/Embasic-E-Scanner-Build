# PUBLIC Gradle build-tool JAR source-byte parity — 7 November 2026

**Scope: four intentionally allowlisted Maven Central build-tool transitives.
Not an Android/Windows scanner release and NOT a complete 147-module SBOM.**

## Why this exists

The PUBLIC root Gradle `buildEnvironment` selected 147 Maven modules
(previous partial inventory: 292 cached artifact SHA-256 hashes).
The previous focused CI verified the actual AGP 8.13.2 and Kotlin Gradle
Plugin 2.3.21 (`gradle813`) binary bytes against Google Maven/Maven Central,
and separately four Android runtime/test JARs. It did not establish a general
source parity check for the other Gradle build-time modules.

This turn adds `scripts/audit_gradle_central_binary_batch.py`, 15 offline
adversarial regression tests, and Android CI source-byte evidence. The
source selection is exactly four named Maven modules; there is **no network
fetch for arbitrary dependency metadata URLs**, no redirect and no auto-fallback
to unknown repository hosts/classifiers.

## Real PUBLIC CI evidence

- Tested commit: `5c751005c7b84500d65c673a83c0b076727cf330`.
- Android Kotlin Foundation:
  https://github.com/ftmstr/Embasic-E-Scanner-Build/actions/runs/42360634578
  (job `128368080483`).
- Step: `Probe four bounded selected Gradle build-tool transitive JARs against Maven Central`:
  **completed/success**, 15/15 synthetic security regressions, four
  upstream JAR byte/size matches, `notSourceVerified=0`.
- Evidence artifact: `android-foundation-dependency-evidence`,
  ID `13569665747`, GitHub retention **14 days**;
  `gradle-central-buildtool-jar-byte-evidence.json` is included.

| Selected Maven artifact (build-tool scope) | Local/official SHA-256 identical |
|---|---|
| `com.google.guava:guava:33.3.1-jre` | `4bf0e2c5af8e4525c96e8fde17a4f7307f97f8478f11c4c8e35a0e3298ae4e90` |
| `com.google.protobuf:protobuf-java:3.25.5` | `8540247fad9e06baefa8fb45eb313802d019f485f14300e0f9d6b556ed88e753` |
| `commons-io:commons-io:2.16.1` | `f41f7baacd716896447ace9758621f62c1c6b0a91d89acee488da26fc477c84f` |
| `org.slf4j:slf4j-api:1.7.30` | `cdba07964d1bb40a0761485c6b1e8c2f8fd9eb1d19c53928ac0d7f9510105c57` |

All four sources use
`https://repo.maven.apache.org/maven2/<group path>/<artifact>/<version>/<artifact>-<version>.jar`,
with explicit coordinates above. Their canonical coordinates and raw source
URLs also appear in the independent job log.

**Interpretation:** bytes retrieved over HTTPS from the allowed Maven
Central endpoint matched the actual local Gradle cached bytes in this CI run.
No detached signature or publisher identity was authenticated.
`publisherSignatureVerified=false`, `originAttributionVerified=false`,
`licenseClosure=NOT_VERIFIED`, `noticeClosure=NOT_VERIFIED`,
`sbomComplete=false`, `releaseApproved=false`.

## Remaining release blockers

- The 147 root plugin modules are NOT all independently byte verified.
  Specifically, this turn verifies four additional ordinary JARs; the
  previous two pinned plugin JARs and four Android runtime/test JARs belong
  to separate, narrowly defined evidence scopes.
- Direct cached POM license-name metadata remains 105 of 147. The other
  42 are still 12 POM-not-cached and 30 without direct license names.
  Source POMs and parent references are **unreviewed supplier claims**,
  not transitive legal approval. Some parent metadata uses dual/copyleft
  license labels requiring separate legal-boundary assessment.
- No independently verified publisher signature, complete SPDX/CycloneDX
  SBOM, linked/embedded release payload inventory, THIRD-PARTY LICENSES
  or approved product root LICENSE.
- Windows App SDK 2.6.4 is only in a disposable .NET 10 Windows restore
  probe. `Microsoft.Windows.SDK.BuildTools@10.0.26100.4654` has a
  legacy supplier `licenseUrl`, not evaluated redistribution rights.
- Android native camera/OCR/PDF, Windows native WinUI 3 scanner,
  QR/HTTPS/WSS secure transfer, cross-device fixture parity and signed
  package smoke remain **NOT VERIFIED**.

**PUBLIC PR #1 remains OPEN/DRAFT/BLOCKED FOR MERGE. No PRIVATE imports,
main merges or force pushes were used.**

## Next bounded engineering task

Expand official-source byte equality to another small source-allowlisted
slice of resolved Gradle build-time modules, including explicit classifier
inventory and provenance gap reasons. Preserve exact dependency scope,
negative security tests and release NO-GO guardrails. Independently review
applicable license texts and actual shipped runtime artifacts before any
commercial release decision.
