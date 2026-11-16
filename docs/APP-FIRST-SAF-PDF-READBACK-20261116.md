# EMBASIC E-SCANNER PUBLIC — Android SAF PDF Readback Integrity Gate (2026-11-16)

## Existing production path and verified bug
The Android Compose preview already used ACTION_CREATE_DOCUMENT and produced an internal
PdfDocument staging file; PdfRenderer reopened the staged PDF and checked page count.
Previously, the app then copied staged bytes via ContentResolver.openOutputStream(uri, "w")
and displayed "PDF kaydedildi" WITHOUT reopening the destination. Providers can truncate,
append, corrupt, silently transform, or deny reading the final document. "w" is not
guaranteed to truncate; a previously longer target may retain trailing bytes.

## Implemented, app-first, no new dependency
* `VerifiedSafPdfTransfer` is a plain Kotlin/JVM testable bounded stream contract.
  It rejects empty/missing/>512MiB stages before opening the provider, reads a
  staged SHA-256 and length, performs an exact bounded copy, closes/flushed
  provider output, and verifies the completed target by independent readback
  with identical length and SHA-256. Any mismatch, short write, exception, or
  missing readback fails closed; no "saved" message.
* Android MainActivity uses explicit ContentResolver mode `"wt"` to request
  truncate-on-write and then closes it before calling openInputStream.
  After matching SHA, it reopens target with PdfRenderer and demands exact
  PDF page count. Failure is visible to the user, including a warning that the
  destination may be partial. Staging retains the original verified PDF until
  the outcome and then removes its private cache copy. Originals, quad, EXIF,
  rotation, Windows RasterPdfWriter and all other workspaces are unchanged.
* Six JVM JUnit tests simulate exact byte roundtrip, short target, same-length
  mutated bytes, exception halfway through output with closure/no false
  readback, unreadable provider and zero-byte staged document rejected before
  touching target. Tests do not pretend to be a live SAF provider.

## Explicit safety boundary — NOT ATOMIC
ACTION_CREATE_DOCUMENT requests a newly created document. A real third-party
SAF provider may create it early, ignore "wt", expose partially written bytes
after a process crash, return a nonseekable PDF descriptor or fail to support
reopen. This implementation detects a bad result AFTER the transfer and does
NOT guarantee power-loss durability, transaction rollback or atomic replacement.
It deliberately does not auto-delete/overwrite the returned URI, because an
untrustworthy provider might have reused an existing user document and deleting
could make the damage worse. If a write fails, user must inspect the target;
success is only reported after hash and PdfRenderer reopening both pass.
Provider-backed atomic commit requires a separate capability-tested adapter and
real Android device/provider acceptance.

## Test and release gates
Native physical Android ACTION_CREATE_DOCUMENT API26/36/provider writing and
PdfRenderer actual target operation NOT VERIFIED; no Android UI automation
runner. Windows WinUI3 interactive GUI and native PDF runtime NOT VERIFIED/BLOCKED.
Android resolved Maven NOTICE inventory remains FAILURE and commercial license,
SBOM/REDIST, signing, rollback, CameraX, OCR/searchable PDF, QR/TLS pairing and
full platform parity remain RELEASE NO-GO. Exact final GitHub commit/CI results
and Drive readback to be recorded in the final per-turn report.
