# PUBLIC private-root owner/UID and NTFS DACL admission — scoped security turn

Date: 2026-11-11 (Türkiye). PUBLIC repository `ftmstr/Embasic-E-Scanner-Build`, branch `fix/pdf-fixture-selftest-20261018`, PR #1 **OPEN / DRAFT**. No PRIVATE/main/merge/force push, root LICENSE change, external runtime package or private sample was introduced.

## Baseline and evidence boundaries

Starting HEAD `e0ec560131721c3321f5940a68a07786af7c435b`: six GitHub Actions workflows completed/success on runs 42884671649, 42884666824, 42884667138, 42884666658, 42884666908 and 42884667232. The prior Drive report includes 75/75 job-step and Android 23/23 JUnit XML evidence, and Windows static-ancestor-symlink/external-hardlink results. The two **existing** common `private-root-alias-v1.tsv` cases remain unchanged.

## Test-first new cases (do not call a queued run RED)

1. Android JUnit added a restrictive 0700 owner-private positive control, followed by an **independent host Linux `chmod 0777` process** that makes the same root group/world writable. Both `open` and read-only recovery must fail closed while its permissions remain insecure.
2. Windows .NET SelfTest added a normal temporary-root positive control followed by an **independent `icacls.exe` process** granting the `Everyone` SID (S-1-1-0) write rights. Both `Open` and `Inspect` must reject it.
3. These cases use the same strict, executable, two-row `tests/golden/private-root-permission-v1.tsv` input: `owner_private_0700 -> ACCEPT/FRESH`, `world_writer_grant -> REJECT/POISONED`. Both suites reject a missing, duplicated or malformed common matrix.
4. Android test-only commit `332e66bf277507a22a5087c8b3750ce07d80d7a0`; Windows test-only joint HEAD `5922f1e9cd0fce2a0932e1438788e32dc778fbc2`. GitHub RED runs exist but remained **QUEUED** at the time of this note. A queued workflow is **NOT RUN**, not RED and not a passing test. Never rewrite this status based on expectations.

## Implemented production-source guardrails

**Android Kotlin:** The existing no-follow lexical-ancestor and `unix:nlink == 1` record checks are kept. `rootIdentity()` now also obtains the root's `unix:uid`, independently gets the current PID's owner UID from `/proc/self`, requires equality, and requires exact POSIX owner read/write/execute permissions (0700). Missing `unix` metadata or inaccessible proc identity rejects. The caller cannot supply a claimed UID. This check covers host JVM contract admission; actual Android UID/storage-provider behavior is **NOT VERIFIED**.

**Windows C# / .NET 10:** The existing NTFS file-ID and reparse/hardlink checks remain. `PrivateRootAcl()` requires a non-NULL DACL, owner SID equal to the current Windows process user, and no root-applicable ALLOW ACE granting filesystem **mutation rights** to principals other than that process user, LOCAL SYSTEM and BUILTIN Administrators. Read-only ACEs are not incorrectly classified as writes; `InheritOnly` ACEs are not applied to the root. Errors fail closed. The implementation uses only .NET/Windows framework APIs already in the target framework; no new package or transitive runtime is added.

**Strict limitations:** The guard is snapshot-oriented, path-based, and neither a cryptographic authorization check nor a complete OS sandbox proof. It does NOT pin a directory fd/handle throughout read/write/rename, validate every ancestor's write/owner ACL, eliminate junction substitution during an open, resolve effective access groups with deny-ACE semantics, guarantee confidentiality against read-only ACLs, or prevent same-account hostile-writer races. In particular, a second same-UID process with access to the root can still race path operations after admission. Directory fsync and power-loss durability are NOT VERIFIED. The Windows test only changes permissions through a separate process; it does not create a competing continuous writer.

## Actual CI status

The test-only HEAD `5922f1e9cd0fce2a0932e1438788e32dc778fbc2` has the six runs 43098744319, 43098744375, 43098744317, 43098744370, 43098744336 and 43098744306. At last observed readback they were **QUEUED**, with no executed red-green result. The later, shared-fixture implementation HEAD must receive its **own** complete run/job/step/log verification before any PASS can be asserted. Do not substitute a historical GREEN run for a new SHA.

## Preserved foundation and release gate

Historical 20/100 real-filesystem synthetic profiles use only 3-byte ASCII per page. Their times are not latency targets, Android device benchmarks, full-resolution image throughput or a 500/1000-page acceptance. The opt-in 500/1000 profile remains **NOT RUN** until independently executed.

**NOT VERIFIED:** physical Android private UID/provider, Windows device ACL/junction/mountpoint race under multiple logon sessions, pinned directory handles/fd, exact file identity across rename, low disk/ENOSPC, kill/restart/power cut, TLS certificate pinning and CSPRNG, real image decode, Android/Windows native UI/OCR/PDF parity and signed package smoke.

**BLOCKED:** 42 Maven child-POM legal review gaps; Windows SDK BuildTools EULA/REDIST; owner approval for root product LICENSE; complete NOTICE/LICENSES/SBOM, signing, rollback. PR #1 must remain DRAFT. RELEASE **NO-GO**.

Progress denominators are stable, not averaged: Android native 0/21=0%; Windows native 0/20=0%; combined parity 0/41=0%; foundation platform 3/6=50%; PUBLIC structure 4/5=80%; signed release 0/8=0%.

## Next critical incremental work

First obtain true RED and GREEN CI evidence (and fix any test/compiler failures); then move to *handle-relative* directory operations on each platform and tests with a second hostile same-account writer, permission-epoch swaps, Windows junction/hardlink races, deterministic ENOSPC/process-kill/restart and recovery. Do not loosen the fail-closed root policy or claim release approval.
