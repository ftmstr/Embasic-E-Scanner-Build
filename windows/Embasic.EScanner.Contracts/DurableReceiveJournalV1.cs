using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Embasic.EScanner.Contracts;

/// <summary>
/// Conservative Windows on-disk receipt adapter for PRE-EXISTING app-private directory.
/// CREATE_NEW token tombstone and immutable per-page receipts are never deleted.
/// Reopen supports READ-ONLY inspection; no automatic resume / new token authorization.
/// Does not establish directory fsync, full power-loss safety, TLS, image decode or
/// protection from a hostile process holding write access to the private directory.
/// </summary>
public sealed class DurableReceiveJournalV1
{
    public enum RecoveryStatus { Fresh, TokenConsumed, Poisoned }
    public sealed record Recovery(RecoveryStatus Status, int ConfirmedPages);
    public const long MaxStageBytes = 32L * 1024 * 1024;
    private const string ClaimFile = "token.claim";
    private const int MaxRecordBytes = 256;
    private readonly object _mutex = new();
    private readonly string _root, _session, _tokenSha;
    private readonly FileId _rootId;
    private readonly long _issued, _expires, _limit;
    private readonly int _maxPages;
    private readonly ReceiveGateV1 _gate;
    private bool _claimed, _stopped;

    private DurableReceiveJournalV1(string root, FileId rootId, string session,
        string tokenSha, long issued, long expires, long limit, int maxPages, ReceiveGateV1 gate)
    {
        _root = root; _rootId = rootId; _session = session; _tokenSha = tokenSha;
        _issued = issued; _expires = expires; _limit = limit; _maxPages = maxPages;
        _gate = gate;
    }

    public static DurableReceiveJournalV1? Open(string? root, string? session, string? tokenSha,
        long issuedAt, long expiresAt, long maxBytes, int maxPages)
    {
        var gate = ReceiveGateV1.Open(session, tokenSha, issuedAt, expiresAt, maxBytes, maxPages);
        if (root is null || gate is null || maxBytes > MaxStageBytes) return null;
        var rootId = GetRootId(root);
        if (rootId is null) return null;
        return new DurableReceiveJournalV1(Path.GetFullPath(root), rootId.Value, session!,
            tokenSha!, issuedAt, expiresAt, maxBytes, maxPages, gate);
    }

    public bool ClaimToken(string? token, long now)
    {
        lock (_mutex)
        {
            if (_stopped || _claimed || !StableRoot() ||
                !PageTransferIntegrity.IsCanonicalSha256(token) ||
                now < _issued || now >= _expires) return false;
            var digest = SHA256.HashData(Encoding.ASCII.GetBytes(token!));
            if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(_tokenSha)))
                return false;
            string record = $"v1|{_session}|{_tokenSha}|{_issued}|{_expires}\n";
            // No overwrite; any interrupted marker is consumed/poisoned on reopen.
            if (!WriteNew(Path.Combine(_root, ClaimFile), Encoding.ASCII.GetBytes(record)))
            {
                _stopped = true;
                return false;
            }
            if (!StableRoot() || _gate.Authenticate(token, now) != ReceiveGateV1.Decision.Accepted)
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
            if (!_claimed || _stopped || !StableRoot()) return false;
            var envelope = PageWireV1.Parse(rawJson, _session, _limit);
            if (envelope is null || bytes is null ||
                !PageWireV1.VerifyBody(envelope, _limit, bytes) ||
                _gate.Propose(rawJson, bytes, now) != ReceiveGateV1.Decision.Accepted)
                return false;
            string index = envelope.Order.ToString("D4", CultureInfo.InvariantCulture);
            string temp = Path.Combine(_root, "stage-" + index + ".tmp");
            string blob = Path.Combine(_root, "page-" + index + ".blob");
            string rec = Path.Combine(_root, "page-" + index + ".rec");
            try
            {
                if (File.Exists(temp) || File.Exists(blob) || File.Exists(rec) ||
                    !WriteNew(temp, bytes)) return Poison();
                var stageId = GetFileId(temp);
                if (stageId is null || ReadBounded(temp, _limit) is not byte[] staged ||
                    !CryptographicOperations.FixedTimeEquals(staged, bytes)) return Poison();
                // File.Move with no overwrite on the SAME private volume. No copy fallback.
                // Windows directory flush and power-loss guarantee remain NOT VERIFIED.
                File.Move(temp, blob);
                if (GetFileId(blob) != stageId ||
                    ReadBounded(blob, _limit) is not byte[] reread ||
                    !PageWireV1.VerifyBody(envelope, _limit, reread)) return Poison();
                string data = $"v1|{envelope.Order}|{envelope.PageId}|{envelope.ByteSize}|{envelope.Mime}|{envelope.Sha256}\n";
                if (!WriteNew(rec, Encoding.ASCII.GetBytes(data)) ||
                    !StableRoot() ||
                    _gate.ConfirmReread(reread, now) != ReceiveGateV1.Decision.Accepted)
                    return Poison();
                return true;
            }
            catch (IOException) { return Poison(); }
            catch (UnauthorizedAccessException) { return Poison(); }
        }
    }

    private bool Poison() { _stopped = true; return false; }
    private bool StableRoot() => GetRootId(_root) == _rootId;

    /// <summary>Read-only recovery. Never grants fresh transport authority.</summary>
    public static Recovery Inspect(string? root, string? session, string? tokenSha,
        long issuedAt, long expiresAt, long maxBytes, int maxPages)
    {
        var bad = new Recovery(RecoveryStatus.Poisoned, 0);
        var gate = Open(root, session, tokenSha, issuedAt, expiresAt, maxBytes, maxPages);
        if (gate is null) return bad;
        try
        {
            var names = Directory.EnumerateFileSystemEntries(gate._root)
                .Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
            if (!gate.StableRoot()) return bad;
            if (names.Count == 0) return new Recovery(RecoveryStatus.Fresh, 0);
            if (!names.Contains(ClaimFile)) return bad;
            var claim = ReadBounded(Path.Combine(gate._root, ClaimFile), MaxRecordBytes);
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
                var data = ReadBounded(Path.Combine(gate._root, rec), MaxRecordBytes);
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
                var body = ReadBounded(Path.Combine(gate._root, blob), maxBytes);
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

    private static bool WriteNew(string path, byte[] data)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.WriteThrough);
            stream.Write(data);
            stream.Flush(flushToDisk: true);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static byte[]? ReadBounded(string path, long maxBytes)
    {
        if (maxBytes < 0 || maxBytes > MaxStageBytes) return null;
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return null;
            FileId? id;
            byte[] bytes;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                       FileShare.None, 4096, FileOptions.SequentialScan))
            {
                id = HandleId(stream.SafeFileHandle);
                if (id is null || stream.Length < 0 || stream.Length > maxBytes) return null;
                bytes = new byte[checked((int)stream.Length)];
                stream.ReadExactly(bytes);
                if (stream.ReadByte() != -1) return null;
            }
            // Close the exclusive read handle before reopening by path for file-ID
            // comparison; otherwise FileShare.None prevents the second open.
            if (GetFileId(path) != id) return null;
            return bytes;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
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
            (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0) return null;
        return new FileId(info.VolumeSerial, info.FileIndexHigh, info.FileIndexLow);
    }

    private static FileId? GetRootId(string root)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
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

    private static FileId? GetFileId(string path)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);
            return HandleId(fs.SafeFileHandle);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }
}
