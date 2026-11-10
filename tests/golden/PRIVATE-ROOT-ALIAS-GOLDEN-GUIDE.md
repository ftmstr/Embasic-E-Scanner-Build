# Private-root aliases: two cross-platform golden adversarial cases

Canonical file: `tests/golden/private-root-alias-v1.tsv`. This file is consumed by
both `DurableReceiveJournalV1Test` (Kotlin/Android JVM, Linux CI) and
`DurableReceiveJournalSelfTest` (C#/.NET10, Windows runner). It has exactly
two non-comment TAB rows with four fields:

`case_id<TAB>root_open<TAB>read_only_recovery<TAB>next_commit`

* `ancestor_symlink`: the leaf root is an ordinary directory, but one parent
  component is a symlink. Root open = REJECT and recovery = POISONED. The
  Windows symlink-creation action may require privilege; when unavailable the
  Windows check explicitly says NOT VERIFIED rather than claiming PASS.
* `external_token_hardlink`: create an exclusive token claim normally,
  then hardlink that claim to a pathname *outside* its trusted root without
  modifying claim bytes. Recovery = POISONED, further page commit = REJECT.
  The test must exercise a real link on the same filesystem, not an emulator.

Real RED BEFORE fix: Windows GitHub run 42883096535 failed
`symlinked ancestor reached private root`; Android run 42883097120 failed
both `ancestorSymlinkMustNotProvidePrivateRoot` and
`externalHardlinkToConsumedTokenMustPoisonJournal`.
The candidate fixes reject symlinks in ancestor components and require one
hardlink to file-backed token/receipt/blob/stage records, using existing
platform OS capabilities without a new dependency.

The same two platform suites also exercise real temporary-file **20- and
100-page** synthetic hash/reopen profiles. The optional 500/1000 profiles
require `EMBASIC_ESCANNER_PERF_EXTENDED=1`. A profile's printed
elapsedMs on GitHub CI is an observation, NOT an end-user latency SLA or
a real full-resolution/CameraX throughput test.

Critically, no claim of production ACL ownership verification, pinned
directory fd, directory fsync, malicious writer TOCTOU resistance, sudden
power loss, Android device provider, Windows NTFS junction, durable
anti-rollback or low-disk safety is established here. See
`docs/ROOT-ANCESTOR-HARDLINK-IO-PROBE-20261110.md`. Release remains NO-GO.
