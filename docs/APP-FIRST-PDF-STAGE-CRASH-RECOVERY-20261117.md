# APP-FIRST PDF cache crash/restart recovery — 2026-11-17

## Context and exact source boundaries
PUBLIC branch `fix/pdf-fixture-selftest-20261018` initially at
`d9d7e96701d6159212bd997ea576b5f8bfc232de`, Draft PR #1 OPEN.
Previous Android PDF stages were created by
`File.createTempFile("escanner-pdf-", ".tmp", cacheDir)`.
On normal success/failure `finally` removed them, but a process crash,
force-stop or sudden reboot left a private plaintext PDF in app cache.
The stage may include scanned document content, so orphan retention is
a privacy, storage and lifecycle risk. Android native SAF document target is
NOT a staging file and must never be deleted by recovery.

## Implemented minimal lifecycle
`PrivatePdfStageCache` handles creation and deletion in the private
application `cacheDir` only; the in-process synchronized active registry
protects exports running during Activity recreation. On Activity onCreate
the IO worker sweeps known orphan temp names before restoring workspace.
On PDF export, it creates a UUID-named stage exclusively and registers it.
The same manager removes it after the SAF SHA-256/PdfRenderer checks, and
the app reports cleanup failures as warnings without falsely claiming
that the temporary file is gone. Regular private original assets under
`filesDir/originals`, other cache files, SAF content URI and Windows app
are never scanned/deleted by this lifecycle.

Recovery is fail-closed for symlinks, matching directories, non-cache paths,
unregistered finish calls and non-directory/symlinked cache roots. It only
deletes direct child regular files with strict exact names
`escanner-pdf-<uuid>.tmp` or legacy `escanner-pdf-<6..24 decimal digits>.tmp`.
The scanner limits deletions per invocation to 128, reports remaining
candidates as failed rather than falsely completed, and can continue on
a later app startup. It never traverses directories or follows links.

## Tests and non-claims
Synthetic JVM tests: exact orphan match with unrelated/private originals
untouched; active stage survives Activity recreation; unregistered finish
rejected; matching directory not traversed; malicious symlink cannot
delete external data; invalid and linked cache roots rejected;
two simultaneous active exports remain protected; 131 orphan cap and retry.
This is source-level lifecycle proof, **not** a physical crash/reboot
proof. Java process-local registry assumes the current single-process
app and is NOT safe alone for future Android multiprocess exporters:
cross-process file locking is a mandatory future gate.

Private cache pruning might also be performed by Android under storage
pressure; recovery does not promise to recover interrupted export bytes.
The SAF target can retain partial bytes after process death: no atomic
Android SAF replace/rollback or power-loss durability is claimed.
Windows WinRT PDF runtime, native Android DocumentsProvider/PdfRenderer
1/20/100 page acceptance and visual rendered-pixel parity remain
NOT VERIFIED/BLOCKED. Maven NOTICE resolved app/test inventory FAILURE,
42 POM rights, SBOM, Windows REDIST/EULA, signing and package smoke
remain RELEASE NO-GO. No external dependency added.
