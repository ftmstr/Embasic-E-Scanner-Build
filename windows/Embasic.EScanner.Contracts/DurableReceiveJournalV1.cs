using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

[assembly: InternalsVisibleTo("Embasic.EScanner.SelfTest")]

namespace Embasic.EScanner.Contracts;

/// <summary>
/// Conservative Windows on-disk receipt adapter for PRE-EXISTING app-private directory.
/// CREATE_NEW token tombstone and immutable per-page receipts are never deleted.
/// Reopen supports READ-ONLY inspection; no automatic resume / new token authorization.
/// Does not establish directory fsync, full power-loss safety, TLS, image decode or
/// protection from a hostile process holding write access to the private directory.
/// </summary>
public sealed class DurableReceiveJournalV1 : IDisposable
{
    public enum RecoveryStatus { Fresh, TokenConsumed, Poisoned }
    public sealed record Recovery(RecoveryStatus Status, int ConfirmedPages);
    public const long MaxStageBytes = 32L * 1024 * 1024;
    private const string ClaimFile = "token.claim";
    private const int MaxRecordBytes = 256;
    private readonly object _mutex = new();
    // Internal adversarial TEST barrier; never assigned by production composition root.
    // Test runner synchronously launches a separate same-SID hostile writer here.
    internal Action? AfterStageCreatedForAdversarialTest { get; set; }
    // Fault injection is internal-only; no production path attaches this delegate.
    internal Action? AfterStagePrefixWrittenForTest { get; set; }
    // Internal, deterministic checkpoint after native handle-relative rename
    // and before receipt creation. Never configured by production callers.
    internal Action? AfterBlobRenamedForTest { get; set; }
    // Synchronized adversarial action at the final live admission boundary.
    // Internal test-only, never wired by the actual journal owner.
    internal Action? BeforeSuccessfulCommitReturnForTest { get; set; }
    // Test-only real same-SID pre-existing writer-handle admission barrier.
    // Synchronized AFTER receipt readback but BEFORE creating live READ pins.
    internal Action? BeforeLivePagePinsForTest { get; set; }
    internal string? LastNativeFailureStage { get; private set; }
    private readonly string _root, _session, _tokenSha;
    private readonly FileId _rootId;
    // A live claim is not only a byte-identical tombstone: its NTFS FILE ID
    // must remain the same as the one created by this journal instance.
    private FileId? _liveClaimId;
    // The previously committed assets must retain NTFS identity even if an
    // attacker substitutes exactly the same bytes under the same name.
    private readonly Dictionary<int, (FileId Blob, FileId Receipt)> _livePageIds = new();
    // Hold real READ-share-only FILE handles for every live confirmed page.
    // This denies new WRITE and DELETE opens by other same-SID processes,
    // including in-place writes that do not change NTFS FILE ID. Release on
    // Dispose; cannot revoke a handle the adversary acquired BEFORE pinning.
    private readonly Dictionary<int, (SafeFileHandle Blob, SafeFileHandle Receipt)> _livePagePins = new();
    // No FILE_SHARE_DELETE: an independent process cannot rename this
    // session's root while the journal owns the directory handle.
    private readonly SafeFileHandle _rootPin;
    // Pin every lexical ancestor of the private root to prohibit a separate
    // process from renaming any path component while the journal is live.
    private readonly SafeFileHandle[] _ancestorPins;
    private bool _disposed;
    private readonly long _issued, _expires, _limit;
    private readonly int _maxPages;
    private readonly ReceiveGateV1 _gate;
    private bool _claimed, _stopped;

    private DurableReceiveJournalV1(string root, FileId rootId, SafeFileHandle rootPin,
        SafeFileHandle[] ancestorPins, string session, string tokenSha, long issued,
        long expires, long limit, int maxPages, ReceiveGateV1 gate)
    {
        _root = root; _rootId = rootId; _rootPin = rootPin;
        _ancestorPins = ancestorPins;
        _session = session; _tokenSha = tokenSha;
        _issued = issued; _expires = expires; _limit = limit; _maxPages = maxPages;
        _gate = gate;
    }

    public static DurableReceiveJournalV1? Open(string? root, string? session, string? tokenSha,
        long issuedAt, long expiresAt, long maxBytes, int maxPages)
    {
        var gate = ReceiveGateV1.Open(session, tokenSha, issuedAt, expiresAt, maxBytes, maxPages);
        if (root is null || gate is null || maxBytes > MaxStageBytes) return null;
        var fullRoot = Path.GetFullPath(root);
        var rootId = GetRootId(fullRoot);
        if (rootId is null) return null;
        var pin = PinRootForSession(fullRoot, rootId.Value);
        if (pin is null) return null;
        var ancestors = PinAncestorsForSession(fullRoot, rootId.Value);
        if (ancestors is null)
        {
            pin.Dispose();
            return null;
        }
        return new DurableReceiveJournalV1(fullRoot, rootId.Value, pin,
            ancestors, session!, tokenSha!, issuedAt, expiresAt, maxBytes, maxPages, gate);
    }

    public bool ClaimToken(string? token, long now)
    {
        lock (_mutex)
        {
            if (_stopped || _claimed || !StableRoot() ||
                !PageTransferIntegrity.IsCanonicalSha256(token) ||
                now < _issued || now >= _expires) return false;
            // Existing entries indicate a consumed/torn session or orphan staging.
            // Refuse to authorize a new token even if the entries are not recognized.
            if (!EmptyRoot())
            {
                _stopped = true;
                return false;
            }
            var digest = SHA256.HashData(Encoding.ASCII.GetBytes(token!));
            if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(_tokenSha)))
                return false;
            string record = $"v1|{_session}|{_tokenSha}|{_issued}|{_expires}\n";
            // No overwrite; any interrupted marker is consumed/poisoned on reopen.
            _liveClaimId = WriteNewRelative(_rootPin, ClaimFile,
                Encoding.ASCII.GetBytes(record));
            if (_liveClaimId is null)
            {
                _stopped = true;
                return false;
            }
            if (_liveClaimId is null || !StableRoot() ||
                _gate.Authenticate(token, now) != ReceiveGateV1.Decision.Accepted)
            {
                _stopped = true;
                return false;
            }
            _claimed = true;
            return true;
        }
    }

    /// <summary>Bounded stage+hash+reread+receipt only, never ScanSession admission.</summary>
    public bool Commit(byte[]? rawJson, byte[]? bytes, long now)
    {
        lock (_mutex)
        {
            if (!_claimed || _stopped) return false;
            // A failed ID/ACL admission is a permanent failure for this
            // instance; a malicious process cannot revive it by restoration.
            if (!StableRoot()) return Poison();
            // A successful earlier receipt is not an immutable trust grant.
            // Revalidate the entire existing ledger before accepting the next
            // page; this requires a private root without a hostile same-dir writer.
            var previous = Inspect(_root, _session, _tokenSha, _issued, _expires,
                _limit, _maxPages);
            if (previous.Status != RecoveryStatus.TokenConsumed ||
                previous.ConfirmedPages != _gate.ConfirmedPages) return Poison("prior-inspect");
            var envelope = PageWireV1.Parse(rawJson, _session, _limit);
            if (envelope is null || bytes is null ||
                !PageWireV1.VerifyBody(envelope, _limit, bytes) ||
                _gate.Propose(rawJson, bytes, now) != ReceiveGateV1.Decision.Accepted)
                return false;
            string index = envelope.Order.ToString("D4", CultureInfo.InvariantCulture);
            string temp = "stage-" + index + ".tmp";
            string blob = "page-" + index + ".blob";
            string rec = "page-" + index + ".rec";
            try
            {
                // Capture the stage FILE ID while the original CREATE handle
                // is still held. Another process cannot replace it silently
                // with an identical-but-distinct NTFS inode before this ID.
                var stageId = WriteNewRelative(_rootPin, temp, bytes,
                    AfterStagePrefixWrittenForTest);
                if (stageId is null) return Poison("stage-create");
                AfterStageCreatedForAdversarialTest?.Invoke();
                if (GetRelativeFileId(_rootPin, temp) != stageId ||
                    ReadBoundedRelative(_rootPin, temp, _limit) is not byte[] staged ||
                    !CryptographicOperations.FixedTimeEquals(staged, bytes)) return Poison("stage-reread");
                // Atomic, no-overwrite same-root rename by pinned SOURCE HANDLE.
                // No File.Move and no copy across volumes; directory durability
                // against sudden power loss remains NOT VERIFIED.
                if (!RenameNoReplaceRelative(_rootPin, temp, blob, stageId.Value))
                    return Poison("stage-rename:" + (LastNativeFailureStage ?? "unspecified"));
                AfterBlobRenamedForTest?.Invoke();
                if (GetRelativeFileId(_rootPin, blob) != stageId ||
                    ReadBoundedRelative(_rootPin, blob, _limit) is not byte[] reread ||
                    !PageWireV1.VerifyBody(envelope, _limit, reread)) return Poison("blob-reread");
                string data = $"v1|{envelope.Order}|{envelope.PageId}|{envelope.ByteSize}|{envelope.Mime}|{envelope.Sha256}\n";
                var writtenReceiptId = WriteNewRelative(_rootPin, rec,
                    Encoding.ASCII.GetBytes(data));
                if (writtenReceiptId is null) return Poison("receipt-create");
                if (!StableRoot() ||
                    _gate.ConfirmReread(reread, now) != ReceiveGateV1.Decision.Accepted)
                    return Poison("receipt-confirm");
                // Freshly read back the full chain after writing a receipt.
                var after = Inspect(_root, _session, _tokenSha, _issued, _expires,
                    _limit, _maxPages);
                if (after.Status != RecoveryStatus.TokenConsumed ||
                    after.ConfirmedPages != _gate.ConfirmedPages) return Poison("post-inspect");
                // Cache the exact identities of this confirmed page; future
                // admissions require every previously accepted inode to match.
                var confirmedBlobId = GetRelativeFileId(_rootPin, blob);
                var confirmedReceiptId = GetRelativeFileId(_rootPin, rec);
                if (confirmedBlobId is null || confirmedReceiptId is null ||
                    confirmedBlobId != stageId ||
                    confirmedReceiptId != writtenReceiptId)
                    return Poison("final-identities");
                // Pin BOTH verified file identities before returning any
                // successful admission. A conflicting prior writer handle
                // makes pinning fail closed rather than weakening sharing.
                BeforeLivePagePinsForTest?.Invoke();
                var blobPin = PinImmutableRead(_rootPin, blob, confirmedBlobId.Value);
                if (blobPin is null) return Poison("blob-pin");
                var receiptPin = PinImmutableRead(_rootPin, rec, confirmedReceiptId.Value);
                if (receiptPin is null)
                {
                    blobPin.Dispose();
                    return Poison("receipt-pin");
                }
                if (!_livePageIds.TryAdd(envelope.Order,
                        (confirmedBlobId.Value, confirmedReceiptId.Value)))
                {
                    blobPin.Dispose();
                    receiptPin.Dispose();
                    return Poison("duplicate-pin");
                }
                _livePagePins.Add(envelope.Order, (blobPin, receiptPin));
                if (!StableRoot()) return Poison("pinned-identities");
                BeforeSuccessfulCommitReturnForTest?.Invoke();
                return true;
            }
            catch (IOException) { return Poison(); }
            catch (UnauthorizedAccessException) { return Poison(); }
        }
    }

    // Required for deterministic release of the Win32 rename lock. SafeFileHandle
    // also has a finalizer as a last resort, but callers MUST dispose sessions.
    public void Dispose()
    {
        lock (_mutex)
        {
            if (_disposed) return;
            _disposed = true;
            _stopped = true;
            foreach (var pair in _livePagePins.Values)
            {
                pair.Blob.Dispose();
                pair.Receipt.Dispose();
            }
            _livePagePins.Clear();
            _rootPin.Dispose();
            foreach (var pin in _ancestorPins) pin.Dispose();
        }
        GC.SuppressFinalize(this);
    }

    private bool EmptyRoot()
    {
        try
        {
            return StableRoot() && !Directory.EnumerateFileSystemEntries(_root).Any() &&
                StableRoot();
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private bool Poison(string stage = "unclassified")
    {
        LastNativeFailureStage = stage;
        _stopped = true;
        return false;
    }
    private bool StableRoot()
    {
        if (_disposed || _rootPin.IsClosed || _rootPin.IsInvalid ||
            _ancestorPins.Any(pin => pin.IsClosed || pin.IsInvalid) ||
            GetRootId(_root) != _rootId ||
            (_claimed && (_liveClaimId is null ||
                GetRelativeFileId(_rootPin, ClaimFile) != _liveClaimId)))
            return false;
        foreach (var (order, expected) in _livePageIds)
        {
            string index = order.ToString("D4", CultureInfo.InvariantCulture);
            if (GetRelativeFileId(_rootPin, "page-" + index + ".blob") != expected.Blob ||
                GetRelativeFileId(_rootPin, "page-" + index + ".rec") != expected.Receipt)
                return false;
        }
        return true;
    }

    /// <summary>Read-only recovery. Never grants fresh transport authority.</summary>
    public static Recovery Inspect(string? root, string? session, string? tokenSha,
        long issuedAt, long expiresAt, long maxBytes, int maxPages)
    {
        var bad = new Recovery(RecoveryStatus.Poisoned, 0);
        using var gate = Open(root, session, tokenSha, issuedAt, expiresAt, maxBytes, maxPages);
        if (gate is null) return bad;
        try
        {
            var names = Directory.EnumerateFileSystemEntries(gate._root)
                .Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
            if (!gate.StableRoot()) return bad;
            if (names.Count == 0) return new Recovery(RecoveryStatus.Fresh, 0);
            if (!names.Contains(ClaimFile)) return bad;
            var claim = ReadBoundedRelative(gate._rootPin, ClaimFile, MaxRecordBytes);
            string expectedClaim = $"v1|{session}|{tokenSha}|{issuedAt}|{expiresAt}\n";
            if (claim is null || !CryptographicOperations.FixedTimeEquals(
                    claim, Encoding.ASCII.GetBytes(expectedClaim))) return bad;
            var seenFiles = new HashSet<string>(StringComparer.Ordinal) { ClaimFile };
            var ids = new HashSet<string>(StringComparer.Ordinal);
            int count = 0;
            while (count < maxPages)
            {
                string number = count.ToString("D4", CultureInfo.InvariantCulture);
                string rec = "page-" + number + ".rec", blob = "page-" + number + ".blob";
                if (!names.Contains(rec) && !names.Contains(blob)) break;
                if (!names.Contains(rec) || !names.Contains(blob)) return bad;
                var data = ReadBoundedRelative(gate._rootPin, rec, MaxRecordBytes);
                if (data is null) return bad;
                var line = Encoding.ASCII.GetString(data);
                if (!line.EndsWith('\n')) return bad;
                var parts = line[..^1].Split('|');
                if (parts.Length != 6 || parts[0] != "v1" ||
                    parts[1] != count.ToString(CultureInfo.InvariantCulture) ||
                    !PageTransferIntegrity.IsCanonicalUuid(parts[2]) ||
                    parts[2] == session || !ids.Add(parts[2]) ||
                    !long.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out long length) ||
                    parts[3] != length.ToString(CultureInfo.InvariantCulture) ||
                    !PageTransferIntegrity.IsConsistentMetadata(session, parts[2], count,
                        length, parts[4], parts[5], maxBytes)) return bad;
                var body = ReadBoundedRelative(gate._rootPin, blob, maxBytes);
                if (!PageTransferIntegrity.VerifyCompleteBytes(session, parts[2], count,
                        length, parts[4], parts[5], maxBytes, body)) return bad;
                seenFiles.Add(rec); seenFiles.Add(blob); count++;
            }
            if (!names.SetEquals(seenFiles) || !gate.StableRoot()) return bad;
            return new Recovery(RecoveryStatus.TokenConsumed, count);
        }
        catch (IOException) { return bad; }
        catch (UnauthorizedAccessException) { return bad; }
    }

    // Native Windows NTFS identity: volume serial + 64-bit file index (not a path string).
    // The caller must still provide an app-private, non-hostile directory. Path swap
    // and multi-process adversarial filesystem tampering are NOT proved safe.
    private readonly record struct FileId(uint Volume, uint High, uint Low);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes, CreatedLow, CreatedHigh, AccessedLow, AccessedHigh;
        public uint WrittenLow, WrittenHigh, VolumeSerial, SizeHigh, SizeLow;
        public uint LinkCount, FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandle", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle,
        out FileInformation info);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);

    private static FileId? HandleId(SafeFileHandle handle)
    {
        if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info) ||
            (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
            // Refuse hardlinks to immutable token/page records, even when
            // bytes still match. Other names enable out-of-root mutation.
            info.LinkCount != 1) return null;
        return new FileId(info.VolumeSerial, info.FileIndexHigh, info.FileIndexLow);
    }

    // Windows user-mode documented Native API. The live journal root SafeFileHandle
    // is the RootDirectory object, so the trusted child name is resolved against
    // THAT directory handle rather than reconstructing a mutable absolute path.
    // This method is deliberately only an immutable-claim FILE-ID probe:
    // staging/open/write/rename are NOT yet fully handle-relative.
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeUnicodeString
    {
        public ushort Length, MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeIoStatusBlock
    {
        public IntPtr Status, Information;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtCreateFile(
        out SafeFileHandle handle, uint desiredAccess,
        ref NativeObjectAttributes attributes, out NativeIoStatusBlock ioStatus,
        IntPtr allocationSize, uint fileAttributes, uint shareAccess,
        uint createDisposition, uint createOptions,
        IntPtr eaBuffer, uint eaLength);

    // File create/open is anchored to the already authenticated root HANDLE.
    // Names are locally generated, single-component ASCII; no slash, reparse,
    // absolute path, alternate data stream or caller-controlled basename.
    private static SafeFileHandle? OpenRelativeFile(SafeFileHandle root, string name,
        uint access, uint disposition, bool writeThrough = false,
        uint shareAccess = 0)
    {
        if (!OperatingSystem.IsWindows() || root.IsClosed || root.IsInvalid ||
            string.IsNullOrEmpty(name) || name.Length > 40 ||
            name is "." or ".." ||
            name.Any(c => !((c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '.' || c == '-')))
            return null;
        IntPtr buffer = IntPtr.Zero, namePointer = IntPtr.Zero;
        try
        {
            buffer = Marshal.StringToHGlobalUni(name);
            var unicode = new NativeUnicodeString
            {
                Length = checked((ushort)(name.Length * 2)),
                MaximumLength = checked((ushort)((name.Length + 1) * 2)),
                Buffer = buffer
            };
            namePointer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeUnicodeString>());
            Marshal.StructureToPtr(unicode, namePointer, false);
            var attributes = new NativeObjectAttributes
            {
                Length = (uint)Marshal.SizeOf<NativeObjectAttributes>(),
                RootDirectory = root.DangerousGetHandle(),
                ObjectName = namePointer,
                Attributes = 0x0040 | 0x1000 // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
            };
            // Open only non-directory files; never follow reparse points.
            // FILE_SYNCHRONOUS_IO_NONALERT requires SYNCHRONIZE access.
            uint options = 0x00000040 | 0x00200000 | 0x00000020;
            if (writeThrough) options |= 0x00000002; // FILE_WRITE_THROUGH
            int status = NtCreateFile(out var child, access, ref attributes,
                out _, IntPtr.Zero, 0x00000080, shareAccess, disposition, options,
                IntPtr.Zero, 0);
            GC.KeepAlive(root);
            if (status != 0 || child is null || child.IsInvalid)
            {
                child?.Dispose();
                return null;
            }
            return child;
        }
        catch (Exception e) when (e is IOException || e is UnauthorizedAccessException ||
            e is ArgumentException || e is OverflowException ||
            e is EntryPointNotFoundException || e is DllNotFoundException)
        {
            return null;
        }
        finally
        {
            if (namePointer != IntPtr.Zero) Marshal.FreeHGlobal(namePointer);
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    private static FileId? GetRelativeFileId(SafeFileHandle rootHandle, string name)
    {
        // FILE_OPEN = 1. Query identity from a pinned directory rather than
        // from a pathname. No path fallback on native API failure.
        using var child = OpenRelativeFile(rootHandle, name, 0x80 | 0x00100000, 1,
            shareAccess: 0x00000001);
        return child is null ? null : HandleId(child);
    }

    // Pin a CONFIRMED file using READ access with FILE_SHARE_READ ONLY.
    // The NTFS sharing contract excludes fresh external WRITE/DELETE handles
    // without blocking the journal's own bounded READ and FILE ID probes.
    // The pin remains live until Dispose() and is not an offline trust anchor.
    private static SafeFileHandle? PinImmutableRead(
        SafeFileHandle root, string name, FileId expected)
    {
        // FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OPEN.
        var pin = OpenRelativeFile(root, name,
            0x00000001 | 0x00000080 | 0x00100000, 1,
            shareAccess: 0x00000001);
        if (pin is null) return null;
        if (HandleId(pin) == expected) return pin;
        pin.Dispose();
        return null;
    }

    // FILE_CREATE = 2: no overwrite, even when a hostile process races the
    // existence check. The FILE ID is sampled before our write handle closes.
    private static FileId? WriteNewRelative(SafeFileHandle root, string name,
        byte[] data, Action? afterPrefixWritten = null)
    {
        try
        {
            using var handle = OpenRelativeFile(root, name,
                0x00000002 | 0x00000080 | 0x00100000, 2, writeThrough: true);
            if (handle is null) return null;
            var id = HandleId(handle);
            if (id is null) return null;
            using (var stream = new FileStream(handle, FileAccess.Write, 4096, false))
            {
                if (afterPrefixWritten is null)
                    stream.Write(data);
                else
                {
                    // Synthetic ENOSPC/error after a real one-byte write.
                    // A thrown IOException leaves an orphan and is fail-closed.
                    int prefix = Math.Min(1, data.Length);
                    stream.Write(data.AsSpan(0, prefix));
                    // Real owner-process Kill must observe a flushed prefix,
                    // not bytes held solely in FileStream's managed buffer.
                    // This is an INTERNAL TEST checkpoint only; it does NOT
                    // assert power-cut/directory metadata fsync durability.
                    stream.Flush(flushToDisk: true);
                    afterPrefixWritten();
                    stream.Write(data.AsSpan(prefix));
                }
                stream.Flush(flushToDisk: true);
                if (HandleId(stream.SafeFileHandle) != id) return null;
            }
            return id;
        }
        catch (Exception e) when (e is IOException || e is UnauthorizedAccessException ||
            e is ArgumentException || e is NotSupportedException)
        {
            return null;
        }
    }

    private static byte[]? ReadBoundedRelative(SafeFileHandle root, string name, long maxBytes)
    {
        if (maxBytes < 0 || maxBytes > MaxStageBytes) return null;
        try
        {
            using var handle = OpenRelativeFile(root, name,
                0x00000001 | 0x00000080 | 0x00100000, 1,
                shareAccess: 0x00000001);
            if (handle is null) return null;
            var id = HandleId(handle);
            if (id is null) return null;
            byte[] data;
            using (var stream = new FileStream(handle, FileAccess.Read, 4096, false))
            {
                if (stream.Length < 0 || stream.Length > maxBytes) return null;
                data = new byte[checked((int)stream.Length)];
                stream.ReadExactly(data);
                if (stream.ReadByte() != -1 ||
                    HandleId(stream.SafeFileHandle) != id) return null;
            }
            // Detect a name substitution between the HANDLE read and our
            // final stable-name check. This is not a continuous race proof.
            if (GetRelativeFileId(root, name) != id) return null;
            return data;
        }
        catch (Exception e) when (e is IOException || e is UnauthorizedAccessException ||
            e is ArgumentException || e is NotSupportedException)
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRenameInfo
    {
        public byte ReplaceIfExists; // FALSE: never overwrite a destination
        public IntPtr RootDirectory;
        public uint FileNameLength;
        public ushort FirstChar; // UTF-16 flexible array starts here
    }

    // Native FileRenameInformation = 10 (NOT Win32 FileRenameInfo = 3).
    // The native call honors OBJECT_ATTRIBUTES-style RootDirectory-relative
    // destination names; no absolute-path or File.Move fallback is allowed.
    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtSetInformationFile(SafeFileHandle handle,
        out NativeIoStatusBlock ioStatus, IntPtr info, uint infoSize,
        int nativeInfoClass);

    // Atomic same-directory no-overwrite rename by SOURCE HANDLE, never
    // File.Move(sourcePath, destPath). Caller checks the pinned FILE ID first.
    private bool RenameNoReplaceRelative(SafeFileHandle root,
        string sourceName, string destName, FileId expected)
    {
        if (destName.Length == 0 || destName.Length > 40 ||
            destName.Any(c => !((c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '.' || c == '-')))
            return false;
        // DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE
        using var source = OpenRelativeFile(root, sourceName,
            0x00010000 | 0x80 | 0x00100000, 1);
        if (source is null) { LastNativeFailureStage = "source-open"; return false; }
        if (HandleId(source) != expected) { LastNativeFailureStage = "source-id"; return false; }
        if (GetRelativeFileId(root, destName) is not null)
        { LastNativeFailureStage = "destination-exists"; return false; }
        IntPtr infoPointer = IntPtr.Zero;
        try
        {
            var filename = Encoding.Unicode.GetBytes(destName);
            int offset = (int)Marshal.OffsetOf<NativeRenameInfo>(
                nameof(NativeRenameInfo.FirstChar));
            int total = checked(offset + filename.Length);
            infoPointer = Marshal.AllocHGlobal(total);
            var info = new NativeRenameInfo
            {
                ReplaceIfExists = 0,
                RootDirectory = root.DangerousGetHandle(),
                FileNameLength = checked((uint)filename.Length)
            };
            Marshal.StructureToPtr(info, infoPointer, false);
            Marshal.Copy(filename, 0, IntPtr.Add(infoPointer, offset), filename.Length);
            // Native FileRenameInformation = 10, ReplaceIfExists = FALSE.
            // NTSTATUS is retained as a nonsecret error code on failure.
            int status = NtSetInformationFile(source, out _, infoPointer,
                checked((uint)total), 10);
            if (status != 0)
            {
                LastNativeFailureStage = "ntstatus-" +
                    unchecked((uint)status).ToString("X8", CultureInfo.InvariantCulture);
                return false;
            }
            GC.KeepAlive(root);
            if (HandleId(source) != expected)
            { LastNativeFailureStage = "post-id-mismatch"; return false; }
            return true;
        }
        catch (Exception e) when (e is IOException || e is UnauthorizedAccessException ||
            e is ArgumentException || e is OverflowException ||
            e is EntryPointNotFoundException || e is DllNotFoundException)
        {
            return false;
        }
        finally
        {
            if (infoPointer != IntPtr.Zero) Marshal.FreeHGlobal(infoPointer);
        }
    }

    // Windows-only admission check. No external NuGet package is introduced.
    // A world-/group-writable or foreign-owner DACL cannot be called app-private.
    // This is an admission guard, NOT pinned HANDLE-relative IO or a defense
    // against a malicious same-user process changing ACLs after validation.
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool PrivateRootAcl(string root, bool requireCallerOwner = true)
    {
        try
        {
            var directory = new DirectoryInfo(root);
            var acl = directory.GetAccessControl(
                AccessControlSections.Owner | AccessControlSections.Access);
            // A NULL DACL implicitly grants everyone complete access.
            var descriptor = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0);
            if (descriptor.DiscretionaryAcl is null) return false;
            var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            // Every ACL check must release its Windows access-token HANDLE.
            // StableRoot/GetRootId can call this hundreds of times per session.
            using var currentIdentity = WindowsIdentity.GetCurrent();
            var processUser = currentIdentity.User;
            if (owner is null || processUser is null) return false;
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var administrators = new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid, null);
            // The session leaf MUST be owned by this process. Its parent may
            // be an OS-owned trust boundary, but never an unknown foreign owner.
            if (requireCallerOwner
                ? !owner.Equals(processUser)
                : !(owner.Equals(processUser) || owner.Equals(system) ||
                    owner.Equals(administrators))) return false;
            // Use ONLY mutating bits. The composite Modify flag also
            // includes READ bits, which would incorrectly reject read-only
            // inherited ACEs on a normal Windows profile directory.
            const FileSystemRights mutatingRights =
                FileSystemRights.WriteData | FileSystemRights.AppendData |
                FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes |
                FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
                FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            foreach (var rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .OfType<FileSystemAccessRule>())
            {
                if (rule.AccessControlType != AccessControlType.Allow ||
                    // Inherit-only ACE does not apply to this directory itself.
                    (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 ||
                    (rule.FileSystemRights & mutatingRights) == 0)
                    continue;
                var principal = rule.IdentityReference as SecurityIdentifier;
                if (principal is null ||
                    !(principal.Equals(processUser) || principal.Equals(system) ||
                      principal.Equals(administrators)))
                    return false;
            }
            return true;
        }
        catch (Exception e) when (e is IOException ||
            e is UnauthorizedAccessException ||
            e is System.Security.SecurityException ||
            e is PlatformNotSupportedException ||
            e is InvalidOperationException)
        {
            return false;
        }
    }

    // Pin the authenticated leaf for the WHOLE live journal session. Opening
    // without FILE_SHARE_DELETE makes MoveFileEx/Directory.Move from a separate
    // process fail while held; no privileged API or new dependency is needed.
    // This does not pin its ancestors, secure same-root child names against a
    // malicious same-user writer, or provide directory fsync durability.
    private static SafeFileHandle? PinRootForSession(string fullRoot, FileId expected)
    {
        if (!OperatingSystem.IsWindows()) return null;
        SafeFileHandle? handle = null;
        try
        {
            // FILE_READ_ATTRIBUTES (0x80) alone is a metadata-only open and
            // is exempt from Win32 share-mode conflicts. To ACTUALLY deny
            // another process DELETE/rename, request directory list/read access.
            const uint fileListDirectory = 0x0001;
            const uint shareReadWrite = 0x01 | 0x02; // intentionally no FILE_SHARE_DELETE
            const uint openExisting = 3;
            const uint directoryAndNoFollow = 0x02000000 | 0x00200000;
            // FILE_TRAVERSE plus FILE_ADD_FILE is needed when a native
            // FileRenameInfo places a child into this pinned RootDirectory.
            handle = CreateFile(fullRoot, fileListDirectory | 0x0020 | 0x0002, shareReadWrite,
                IntPtr.Zero, openExisting, directoryAndNoFollow, IntPtr.Zero);
            if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info) ||
                (info.Attributes & (uint)FileAttributes.Directory) == 0 ||
                (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
                new FileId(info.VolumeSerial, info.FileIndexHigh, info.FileIndexLow) != expected ||
                GetRootId(fullRoot) != expected)
            {
                handle.Dispose();
                return null;
            }
            return handle;
        }
        catch (IOException) { handle?.Dispose(); return null; }
        catch (UnauthorizedAccessException) { handle?.Dispose(); return null; }
    }

    // CreateFileW with FILE_LIST_DIRECTORY, not attribute-only metadata,
    // ensures Windows share-mode checks enforce NO FILE_SHARE_DELETE for each
    // lexical ancestor. Fail closed if even one ancestor cannot be pinned.
    // Parent handles do not yet make child file operations HANDLE-relative.
    private static SafeFileHandle[]? PinAncestorsForSession(string root, FileId expected)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var pinned = new List<SafeFileHandle>();
        bool accepted = false;
        try
        {
            var current = Directory.GetParent(root);
            while (current is not null)
            {
                if ((File.GetAttributes(current.FullName) & FileAttributes.ReparsePoint) != 0)
                    return null;
                var handle = CreateFile(current.FullName, 0x0001, 0x0001 | 0x0002,
                    IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    handle.Dispose();
                    return null;
                }
                if (!GetFileInformationByHandle(handle, out var info) ||
                    (info.Attributes & (uint)FileAttributes.Directory) == 0 ||
                    (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0)
                {
                    handle.Dispose();
                    return null;
                }
                pinned.Add(handle);
                current = current.Parent;
            }
            // After every ancestor handle is held, recheck original leaf ID,
            // owner, private DACL and lexical reparse chain as one admission.
            if (GetRootId(root) != expected) return null;
            accepted = true;
            return pinned.ToArray();
        }
        catch (Exception e) when (e is IOException ||
            e is UnauthorizedAccessException || e is System.Security.SecurityException)
        {
            return null;
        }
        finally
        {
            if (!accepted) foreach (var handle in pinned) handle.Dispose();
        }
    }

    private static FileId? GetRootId(string root)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            // OPEN_REPARSE_POINT guards the final component, not its parents.
            // Windows can otherwise follow C:\\base\\alias\\session even if the
            // final "session" directory itself is a normal directory.
            var current = new DirectoryInfo(Path.GetFullPath(root));
            while (current is not null)
            {
                var attributes = File.GetAttributes(current.FullName);
                if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                    (attributes & FileAttributes.Directory) == 0) return null;
                current = current.Parent;
            }
            // Harden the immediate ancestor: a private leaf inside a writable
            // parent can be redirected BEFORE its handle is acquired. Other
            // ancestors are handle-pinned for the live session below.
            var parent = Directory.GetParent(Path.GetFullPath(root));
            if (parent is null || !PrivateRootAcl(parent.FullName, requireCallerOwner: false) ||
                !PrivateRootAcl(root)) return null;
            using var handle = CreateFile(Path.GetFullPath(root), 0x80, 7, IntPtr.Zero,
                3, 0x02000000 | 0x00200000, IntPtr.Zero); // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
            // GetFileInformationByHandle succeeds for regular files too: the
            // trusted root MUST be a directory, never an arbitrary file.
            if (handle.IsInvalid ||
                !GetFileInformationByHandle(handle, out var info) ||
                (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
                (info.Attributes & (uint)FileAttributes.Directory) == 0)
                return null;
            return new FileId(info.VolumeSerial, info.FileIndexHigh, info.FileIndexLow);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }


}
