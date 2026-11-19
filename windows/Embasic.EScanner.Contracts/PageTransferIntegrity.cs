using System.Security.Cryptography;

namespace Embasic.EScanner.Contracts;

/// <summary>
/// Untrusted page-transfer envelope preflight, independent of WinUI and transport.
/// This checks canonical fields, complete length and SHA-256 only. It does NOT
/// parse raw JSON, authenticate TLS, decode an image or grant domain admission.
/// </summary>
public static class PageTransferIntegrity
{
    private const string NilUuid = "00000000-0000-0000-0000-000000000000";

    public static bool IsCanonicalUuid(string? value)
    {
        if (value is null || value.Length != 36 || value == NilUuid)
            return false;
        for (var i = 0; i < value.Length; i++)
        {
            var ch = value[i];
            if (i is 8 or 13 or 18 or 23)
            {
                if (ch != '-') return false;
            }
            else if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
            {
                return false;
            }
        }
        return true;
    }

    public static bool IsCanonicalSha256(string? value)
    {
        if (value is null || value.Length != 64) return false;
        foreach (var ch in value)
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
                return false;
        return true;
    }

    public static bool IsConsistentMetadata(
        string? sessionId, string? pageId, int order, long declaredBytes,
        string? mime, string? sha256, long maxBytes) =>
        IsCanonicalUuid(sessionId) && IsCanonicalUuid(pageId) &&
        sessionId != pageId && order >= 0 && maxBytes > 0 &&
        declaredBytes > 0 && declaredBytes <= maxBytes &&
        (mime is "image/jpeg" or "image/png") && IsCanonicalSha256(sha256);

    public static bool VerifyCompleteBytes(
        string? sessionId, string? pageId, int order, long declaredBytes,
        string? mime, string? sha256, long maxBytes, byte[]? bytes)
    {
        if (!IsConsistentMetadata(sessionId, pageId, order, declaredBytes, mime, sha256, maxBytes)
            || bytes is null || bytes.LongLength != declaredBytes)
            return false;
        var expected = Convert.FromHexString(sha256!);
        var actual = SHA256.HashData(bytes);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
