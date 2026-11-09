# PUBLIC exact Jakarta Activation API 1.2.1 EDL metadata review (9 Nov 2026)

**STATUS: TECHNICAL EVIDENCE ONLY, NOT A LICENCE GRANT.**
Only ftmstr/Embasic-E-Scanner-Build branch fix/pdf-fixture-selftest-20261018.
No PRIVATE/main/merge/force or unapproved product root LICENSE. Release NO-GO.

## Why this exact component?

PUBLIC Gradle root/app buildEnvironment selects
pkg:maven/jakarta.activation/jakarta.activation-api@1.2.1 within
42 direct child POM metadata gaps. The CHILD Maven POM itself has
no direct licenses declaration. Its immediate parent
com.sun.activation:all:1.2.1 has a supplier EDL 1.0 declaration.
Its organization-wide ancestor org.eclipse.ee4j:project:1.0.2
lists EPL 2.0 and GPLv2 with Classpath Exception as *parent*
supplier metadata. Those are NOT an approved effective licence of
any individual child class/JAR or the final E-Scanner package.

## Immutable historical supplier release source

Original supplier repository jakartaee/jaf-api has annotated tag 1.2.1,
tag SHA 74a1e74bf03213a0bb16e8e2392933aa47c233f3,
peeled commit 41bad0bd6ba821abd8652c80e8e3c50b55851da2.
GitHub verification says verified=false, reason=unsigned. The tag
is **not cryptographically verified**, even when contents match.

Three source files at that exact commit:
- LICENSE.md: Git blob SHA1 e0358f972175d83cc567fcd129cc205ea9d40ff0.
  Supplier includes BSD three-clause-style text, source/binary notice
  requirements, non-endorsement and copyright/disclaimer language.
- NOTICE.md: Git blob SHA1 d6492f81ccce4efec1e8d03248ca64d3b26c164f.
  Supplier states EDL v1.0 and SPDX-License-Identifier BSD-3-Clause;
  upstream JUnit 4.12 is mentioned as project third-party content,
  not evidence of this module's Android APK runtime inclusion.
- activationapi/pom.xml: Git blob SHA1
  09697c4589fb48882fb8ad28aaffe5d097054351;
  source POM header references EDL-1.0 and SPDX BSD-3-Clause;
  supplier description calls this an API/compile module without
  implementation classes. This is source context, not package proof.

Pinned commit raw URLs avoid mutable master or moving tag resolution.
An upstream license declaration is not a chosen legal option,
a reviewed source-file header obligation or E-Scanner redistribution
permission. Classpath Exception in the EE4J ancestor must not be
blindly inherited by the API JAR.

## Exact Maven coordinates / legitimate differing-group parent

Official child POM and JAR:
https://repo.maven.apache.org/maven2/jakarta/activation/jakarta.activation-api/1.2.1/jakarta.activation-api-1.2.1.pom
https://repo.maven.apache.org/maven2/jakarta/activation/jakarta.activation-api/1.2.1/jakarta.activation-api-1.2.1.jar

Official immediate parent:
https://repo.maven.apache.org/maven2/com/sun/activation/all/1.2.1/all-1.2.1.pom

The child inherits 1.2.1 from a *different Maven group*
com.sun.activation. The audit recognizes exactly this source
parent and rejects wrong version/ancestor. Do not require a
child and parent to have identical groupId.

## Fail-closed PUBLIC CI technical gate

scripts/audit_activation_api121_exact_license.py compares:
- actual selected Gradle buildEnvironment child POM/JAR local
  SHA-256 and byte counts against exact Maven Central bytes;
- actual cached immediate parent POM SHA-256 against Maven bytes;
- exact historic Git blob identity for LICENSE.md, NOTICE.md
  and activationapi/pom.xml; check tagged licence/notice and
  Maven API POM source text, with exact source-POM byte parity;
- bounded JAR ZIP member audit for META-INF/LICENSE.md and
  META-INF/NOTICE.md, comparison of each with tagged source bytes;
- exact selected root/app plugin scope vs independent partial
  Android runtime/test graph, rejecting a newly appearing
  product/test runtime dependency pending legal review.

The allowlist contains only six literal pinned HTTPS URLs, never
untrusted arbitrary endpoints. It rejects redirects, malformed
POMs, unsafe ZIP paths/symlinks, duplicate or absent licence
files, text drift, forged legal clearance and unbounded byte sizes.
tests/test_activation_api121_exact_license.py holds 34
generated adversarial/synthetic cases. No real UYAP files.

Output is CI artifact
activation-api121-exact-source-license-evidence.json. This is
metadata, not a complete third-party licence/NOTICE package or SBOM,
publisher signature, license election or legal clearance. Any source
parity is a verified result ONLY if real GitHub Actions run/job/step/log
finishes successfully. Upstream release/NOTICE content does not prove
signed APK/AAB exclusion.

## Open decisions

Even if raw bytes match, supplier BSD-3-Clause/EDL 1.0 applicable
source-file terms, non-endorsement, source/binary copyright notices,
runtime/package file inclusion, transitive obligations, all licences,
and commercial redistribution rights need a separate human legal and
signed-release inventory review. All 42 child direct metadata gaps
stay OPEN. The other three remaining complex-parent metadata groups
must be reviewed separately, never inherited automatically.

Independent Windows blocker: Microsoft.Windows.SDK.BuildTools
10.0.26100.4654 exact EULA/REDIST and per-file shipment rights
remain NOT VERIFIED; a NuGet package hash is not a legal grant.
Kök ürün LICENSE dosyası ancak hak sahibi onayıyla eklenebilir.

Native parity 0/41, foundation 3/6, structural 4/5, release
0/8; conditional 31 Dec 2027 is planning, not an ETA or promise.
