using System.Security.Cryptography;
using System.Text;

namespace Embasic.EScanner.Contracts;

/// <summary>
/// In-memory guard only, never TLS/QR, real disk staging or a domain transition.
/// Caller provides trusted session, token SHA256, clock and bounds.
/// Each instance serializes mutation to prevent concurrent token/page replay.
/// </summary>
public sealed class ReceiveGateV1
{
    public enum Phase { Pending, Authorized, Staged, Closed }
    public enum Decision { Accepted, Rejected }

    private readonly object _mutex = new();
    private readonly string _session;
    private readonly byte[] _tokenHash;
    private readonly long _issued;
    private readonly long _expiry;
    private readonly long _limit;
    private readonly int _maxPages;
    private readonly HashSet<string> _pageIds = new(StringComparer.Ordinal);
    private long _lastClock;
    private Phase _phase = Phase.Pending;
    private int _nextOrder;
    private CanonicalPageWireV1? _pending;

    private ReceiveGateV1(string session, byte[] tokenHash, long issued, long expiry, long limit, int maxPages)
    {
        _session = session;
        _tokenHash = tokenHash;
        _issued = issued;
        _expiry = expiry;
        _limit = limit;
        _maxPages = maxPages;
        _lastClock = issued;
    }

    public const long MaxTtlMillis = 300_000;
    public const int MaxPages = 1000;

    public static ReceiveGateV1? Open(
        string? expectedSessionId, string? expectedTokenSha256,
        long issuedAtMillis, long expiresAtMillis, long maxPageBytes, int maxPages)
    {
        if (!PageTransferIntegrity.IsCanonicalUuid(expectedSessionId) ||
            !PageTransferIntegrity.IsCanonicalSha256(expectedTokenSha256) ||
            issuedAtMillis < 0 || expiresAtMillis <= issuedAtMillis ||
            expiresAtMillis - issuedAtMillis > MaxTtlMillis ||
            maxPageBytes <= 0 || maxPages is < 1 or > MaxPages)
            return null;
        return new ReceiveGateV1(expectedSessionId!, Convert.FromHexString(expectedTokenSha256!),
            issuedAtMillis, expiresAtMillis, maxPageBytes, maxPages);
    }

    public Phase CurrentPhase { get { lock (_mutex) return _phase; } }
    public int ConfirmedPages { get { lock (_mutex) return _nextOrder; } }

    /// <summary>Token is 32 cryptographically random bytes encoded as lowercase hex.
    /// Hash is retained, not the raw token. No peer TLS or restart durability implied.</summary>
    public Decision Authenticate(string? presentedToken, long nowMillis)
    {
        lock (_mutex)
        {
            if (!TimeAllowed(nowMillis) || _phase != Phase.Pending ||
                !PageTransferIntegrity.IsCanonicalSha256(presentedToken))
                return Decision.Rejected;
            var actual = SHA256.HashData(Encoding.ASCII.GetBytes(presentedToken!));
            if (!CryptographicOperations.FixedTimeEquals(actual, _tokenHash))
                return Decision.Rejected;
            _phase = Phase.Authorized;
            return Decision.Accepted;
        }
    }

    /// <summary>Proposal checks raw wire plus complete body, DOES NOT write a file.</summary>
    public Decision Propose(byte[]? rawJson, byte[]? completeBytes, long nowMillis)
    {
        lock (_mutex)
        {
            if (!TimeAllowed(nowMillis) || _phase != Phase.Authorized || _nextOrder >= _maxPages)
                return Decision.Rejected;
            var envelope = PageWireV1.Parse(rawJson, _session, _limit);
            if (envelope is null || envelope.Order != _nextOrder ||
                _pageIds.Contains(envelope.PageId) ||
                !PageWireV1.VerifyBody(envelope, _limit, completeBytes))
                return Decision.Rejected;
            _pending = envelope;
            _phase = Phase.Staged;
            return Decision.Accepted;
        }
    }

    /// <summary>Caller must supply independent staged source bytes via reread.
    /// Atomicity/durability of real disk staging, image decoding and trusted
    /// file identity are OUT OF SCOPE and still mandatory before domain admission.</summary>
    public Decision ConfirmReread(byte[]? stagedReread, long nowMillis)
    {
        lock (_mutex)
        {
            if (!TimeAllowed(nowMillis) || _phase != Phase.Staged || _pending is null ||
                !PageWireV1.VerifyBody(_pending, _limit, stagedReread) ||
                _pageIds.Contains(_pending.PageId) || _pending.Order != _nextOrder ||
                _nextOrder >= _maxPages)
                return Decision.Rejected;
            _pageIds.Add(_pending.PageId);
            _nextOrder++;
            _pending = null;
            _phase = Phase.Authorized;
            return Decision.Accepted;
        }
    }

    public Decision Close()
    {
        lock (_mutex)
        {
            if (_phase == Phase.Closed) return Decision.Rejected;
            _phase = Phase.Closed;
            _pending = null;
            return Decision.Accepted;
        }
    }

    private bool TimeAllowed(long nowMillis)
    {
        if (_phase == Phase.Closed || nowMillis < _issued || nowMillis < _lastClock)
            return false;
        _lastClock = nowMillis;
        if (nowMillis >= _expiry)
        {
            _phase = Phase.Closed;
            _pending = null;
            return false;
        }
        return true;
    }
}
