using System.Globalization;
using System.Text;

namespace Embasic.EScanner.Contracts;

/// <summary>Untrusted, bounded wire metadata; never a domain/ScanSession transition.</summary>
public sealed record CanonicalPageWireV1(
    int ProtocolVersion, string SessionId, string PageId, int Order,
    long ByteSize, string Mime, string Sha256, string CanonicalJson);

public static class PageWireV1
{
    public const int MaxWireBytes = 4096;
    private static readonly HashSet<string> Keys = new(StringComparer.Ordinal)
    { "protocolVersion", "sessionId", "pageId", "order", "byteSize", "mime", "sha256" };
    private static readonly HashSet<string> NumericKeys = new(StringComparer.Ordinal)
    { "protocolVersion", "order", "byteSize" };

    /// <summary>Expected session and max size come from the trusted caller, never JSON.</summary>
    public static CanonicalPageWireV1? Parse(byte[]? raw, string? expectedSessionId, long maxBytes)
    {
        if (!PageTransferIntegrity.IsCanonicalUuid(expectedSessionId) || maxBytes <= 0 ||
            raw is null || raw.Length is 0 or > MaxWireBytes)
            return null;
        foreach (byte b in raw)
            if (!((b >= 0x20 && b <= 0x7e) || b == 9 || b == 10 || b == 13))
                return null;
        try
        {
            var fields = new Reader(Encoding.ASCII.GetString(raw)).ReadObject();
            if (fields.Count != Keys.Count) return null;
            string Get(string key, bool isString)
            {
                if (!fields.TryGetValue(key, out var field) || field.IsString != isString)
                    throw new FormatException("missing or mismatched wire field");
                return field.Text;
            }
            if (!int.TryParse(Get("protocolVersion", false), NumberStyles.None,
                    CultureInfo.InvariantCulture, out var version) || version != ScanContract.ProtocolVersion ||
                !int.TryParse(Get("order", false), NumberStyles.None,
                    CultureInfo.InvariantCulture, out var order) ||
                !long.TryParse(Get("byteSize", false), NumberStyles.None,
                    CultureInfo.InvariantCulture, out var size)) return null;
            var session = Get("sessionId", true);
            var page = Get("pageId", true);
            var mime = Get("mime", true);
            var sha = Get("sha256", true);
            if (!string.Equals(session, expectedSessionId, StringComparison.Ordinal) ||
                !PageTransferIntegrity.IsConsistentMetadata(session, page, order, size, mime, sha, maxBytes))
                return null;
            var canonical = $"{{\"protocolVersion\":1,\"sessionId\":\"{session}\",\"pageId\":\"{page}\"," +
                $"\"order\":{order},\"byteSize\":{size},\"mime\":\"{mime}\",\"sha256\":\"{sha}\"}}";
            return new CanonicalPageWireV1(version, session, page, order, size, mime, sha, canonical);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>Hash/length still cannot authenticate a sender or validate an image.</summary>
    public static bool VerifyBody(CanonicalPageWireV1 envelope, long maxBytes, byte[]? bytes) =>
        PageTransferIntegrity.VerifyCompleteBytes(envelope.SessionId, envelope.PageId,
            envelope.Order, envelope.ByteSize, envelope.Mime, envelope.Sha256, maxBytes, bytes);

    private sealed class Reader(string text)
    {
        private int _pos;
        private char? Peek() => _pos < text.Length ? text[_pos] : null;
        private void SkipSpace()
        {
            while (Peek() is ' ' or '\t' or '\n' or '\r') _pos++;
        }
        private void Expect(char ch)
        {
            SkipSpace();
            if (Peek() != ch) throw new FormatException("unexpected wire token");
            _pos++;
        }
        private string ReadString()
        {
            if (Peek() != '"') throw new FormatException("missing quote");
            _pos++;
            int start = _pos;
            while (Peek() is char ch)
            {
                _pos++;
                if (ch == '"') return text[start..(_pos - 1)];
                if (ch is '\\' or < ' ' or > '~')
                    throw new FormatException("escapes and controls forbidden");
            }
            throw new FormatException("unterminated string");
        }
        private string ReadNumber()
        {
            int start = _pos;
            if (Peek() is not (>= '0' and <= '9'))
                throw new FormatException("noncanonical number");
            while (Peek() is >= '0' and <= '9') _pos++;
            string number = text[start.._pos];
            if (number.Length > 1 && number[0] == '0')
                throw new FormatException("leading zero");
            return number;
        }
        public Dictionary<string, (string Text, bool IsString)> ReadObject()
        {
            var fields = new Dictionary<string, (string Text, bool IsString)>(StringComparer.Ordinal);
            Expect('{');
            SkipSpace();
            if (Peek() == '}') throw new FormatException("empty object");
            while (true)
            {
                SkipSpace();
                string key = ReadString();
                if (!Keys.Contains(key) || fields.ContainsKey(key) || fields.Count >= Keys.Count)
                    throw new FormatException("unknown or duplicate field");
                Expect(':');
                SkipSpace();
                bool isString = !NumericKeys.Contains(key);
                fields.Add(key, (isString ? ReadString() : ReadNumber(), isString));
                SkipSpace();
                if (Peek() == ',') { _pos++; continue; }
                if (Peek() == '}') { _pos++; break; }
                throw new FormatException("unexpected object delimiter");
            }
            SkipSpace();
            if (_pos != text.Length) throw new FormatException("trailing content");
            return fields;
        }
    }
}
