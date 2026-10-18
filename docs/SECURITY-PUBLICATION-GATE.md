# Public publication / release gates

## Source import — NO-GO until verified
1. Independently audit every proposed source file, binary, filename, metadata and fixture. Reject private data and secret material.
2. Reconstruct only an allowlisted working-tree snapshot; **never git push --mirror**, copy .git, or import private commit history.
3. Confirm source ownership, SPDX-compatible third-party usage, every direct and transitive license, package binaries and copyright notices.
4. Inspect Gradle wrapper provenance/checksum before use; never copy a wrapper jar blindly.
5. Validate Android and Windows dependency inventories, NOTICE/LICENSES and an SBOM before release.
6. Enforce least-privilege CI, untrusted PR execution without elevated tokens, no upload of logs containing secrets, and no signing credentials.

## Runtime security — NOT IMPLEMENTED
Immutable original image, raw→parse→validate→domain, max byte/dimension admission, hash checks and stage→validate→atomic replace are mandatory. Connection security requires TLS, QR fingerprint pinning, short-lived one-time tokens and session replay prevention.

## Evidence semantics
A YAML workflow file is not a build success. Track run, job, step, log and artifact independently. A job with no executed steps is **BLOCKED PRE-STEP** and product tests are **NOT RUN**, not FAIL.
