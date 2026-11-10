using System.Text;
using Embasic.EScanner.Contracts;
if (!ScanContract.IsSupportedVersion(1) || ScanContract.IsSupportedVersion(0) || ScanContract.IsSupportedVersion(2) || !ScanContract.IsValidPageOrder(0) || ScanContract.IsValidPageOrder(-1))
{
    Console.Error.WriteLine("FAIL: contract boundary");
    return 1;
}
Console.WriteLine("PASS: 5 contract assertions");

var fixture = SyntheticPdf.Create();
if (!SyntheticPdf.VerifyFixture(fixture))
{
    Console.Error.WriteLine("FAIL: synthetic PDF structure");
    return 1;
}
var damaged = (byte[])fixture.Clone();
damaged[0] = (byte)'X';
if (SyntheticPdf.VerifyFixture(damaged))
{
    Console.Error.WriteLine("FAIL: corrupt PDF header accepted");
    return 1;
}
damaged = (byte[])fixture.Clone();
damaged[^2] = (byte)'X';
if (SyntheticPdf.VerifyFixture(damaged))
{
    Console.Error.WriteLine("FAIL: corrupt PDF trailer accepted");
    return 1;
}
Console.WriteLine("PASS: 3 synthetic PDF fixture assertions");

// Closed-world fixture admission: malformed xref metadata, tampered objects,
// and oversized/invalid byte streams must never be admitted as canonical.
var fixtureText = Encoding.ASCII.GetString(fixture);
var tableStart = fixtureText.IndexOf("xref\n0 6\n", StringComparison.Ordinal);
var firstXrefEntry = tableStart + "xref\n0 6\n".Length + "0000000000 65535 f \n".Length;
if (tableStart < 0 || firstXrefEntry + 40 >= fixture.Length)
{
    Console.Error.WriteLine("FAIL: synthetic xref test fixture layout");
    return 1;
}
var firstOffset = fixtureText.Substring(firstXrefEntry, 10);
var misplacedOffset = (int.Parse(firstOffset, System.Globalization.CultureInfo.InvariantCulture) + 1)
    .ToString("D10", System.Globalization.CultureInfo.InvariantCulture);
var reversedXrefEntries = (byte[])fixture.Clone();
Array.Copy(fixture, firstXrefEntry + 20, reversedXrefEntries, firstXrefEntry, 20);
Array.Copy(fixture, firstXrefEntry, reversedXrefEntries, firstXrefEntry + 20, 20);
var alteredStreamByte = (byte[])fixture.Clone();
var streamIndex = fixtureText.IndexOf("/F1 18 Tf", StringComparison.Ordinal);
if (streamIndex < 0)
{
    Console.Error.WriteLine("FAIL: synthetic stream test fixture layout");
    return 1;
}
alteredStreamByte[streamIndex + 4] = 0xFF;

var rejectedFixtures = new (string Name, byte[]? Bytes)[]
{
    ("null", null),
    ("empty", Array.Empty<byte>()),
    ("truncated", fixture[..99]),
    ("xref subsection origin", ReplaceAscii(fixture, "xref\n0 6\n", "xref\n1 6\n")),
    ("xref free entry flag", ReplaceAscii(fixture, "0000000000 65535 f \n", "0000000000 65535 n \n")),
    ("xref live entry generation", ReplaceAscii(fixture, " 00000 n \n", " 00001 n \n")),
    ("xref object offset beyond file", ChangeAscii(fixture, firstXrefEntry, '9')),
    ("xref object offset off-by-one", ReplaceAscii(fixture, firstOffset + " 00000 n \n", misplacedOffset + " 00000 n \n")),
    ("reversed object offsets", reversedXrefEntries),
    ("wrong first object number", ReplaceAscii(fixture, "1 0 obj\n", "2 0 obj\n")),
    ("missing endobj", ReplaceAscii(fixture, "endobj\n", "endobX\n")),
    ("startxref wrong offset", ReplaceAscii(fixture, "startxref\n" + tableStart + "\n", "startxref\n0\n")),
    ("startxref integer overflow", ReplaceAscii(fixture, "startxref\n" + tableStart + "\n", "startxref\n999999999999999999999999999\n")),
    ("oversized injected trailer", ReplaceAscii(fixture, "trailer\n", new string('X', 70 * 1024) + "trailer\n")),
    ("extra bytes before EOF", ReplaceAscii(fixture, "%%EOF\n", "EXTRA%%EOF\n")),
    ("invalid ASCII in content stream", alteredStreamByte),
};
foreach (var (name, input) in rejectedFixtures)
{
    if (SyntheticPdf.VerifyFixture(input))
    {
        Console.Error.WriteLine("FAIL: synthetic PDF verifier accepted " + name);
        return 1;
    }
}
Console.WriteLine($"PASS: {rejectedFixtures.Length} adversarial synthetic PDF rejections");

const string sessionId = "01234567-89ab-4cde-8f01-23456789abcd";
const string pageId = "11234567-89ab-4cde-8f01-23456789abcd";
const string abcSha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
var abc = Encoding.ASCII.GetBytes("abc");
bool Check(string? sid = sessionId, string? pid = pageId, int order = 0,
    long declared = 3, string? mime = "image/jpeg", string? sha = abcSha256,
    long cap = 1024, byte[]? bytes = null)
    => PageTransferIntegrity.VerifyCompleteBytes(sid, pid, order, declared, mime,
        sha, cap, bytes ?? abc);
if (!PageTransferIntegrity.IsCanonicalUuid(sessionId) ||
    !PageTransferIntegrity.IsCanonicalUuid(pageId) ||
    !PageTransferIntegrity.IsCanonicalSha256(abcSha256) ||
    !PageTransferIntegrity.IsConsistentMetadata(sessionId, pageId, 0, 3,
        "image/jpeg", abcSha256, 3) ||
    !Check() || !Check(order: int.MaxValue) || !Check(mime: "image/png"))
{
    Console.Error.WriteLine("FAIL: canonical synthetic transfer envelope positive");
    return 1;
}
var badEnvelopes = new (string Name, bool WasAccepted)[]
{
    ("null session", Check(sid: null)),
    ("uppercase session UUID", Check(sid: sessionId.ToUpperInvariant())),
    ("uppercase page UUID", Check(pid: pageId.ToUpperInvariant())),
    ("nil page UUID", Check(pid: "00000000-0000-0000-0000-000000000000")),
    ("session and page collision", Check(pid: sessionId)),
    ("page UUID missing hyphens", Check(pid: pageId.Replace("-", ""))),
    ("negative order", Check(order: -1)),
    ("minimum signed order", Check(order: int.MinValue)),
    ("zero declared bytes", Check(declared: 0)),
    ("negative declared bytes", Check(declared: -1)),
    ("declared bytes smaller than body", Check(declared: 2)),
    ("declared bytes larger than body", Check(declared: 4)),
    ("overlong declared size", Check(declared: long.MaxValue, cap: long.MaxValue)),
    ("zero cap", Check(cap: 0)),
    ("negative cap", Check(cap: -1)),
    ("cap lower than body", Check(cap: 2)),
    ("wrong MIME casing", Check(mime: "IMAGE/JPEG")),
    ("unapproved MIME", Check(mime: "image/svg+xml")),
    ("MIME parameter", Check(mime: "image/jpeg; charset=utf-8")),
    ("null MIME", Check(mime: null)),
    ("null SHA", Check(sha: null)),
    ("uppercase SHA", Check(sha: abcSha256.ToUpperInvariant())),
    ("wrong SHA", Check(sha: new string('0', 64))),
    ("nonhex SHA", Check(sha: new string('g', 64))),
    ("modified byte stream", Check(bytes: Encoding.ASCII.GetBytes("abd"))),
    ("truncated byte stream", Check(bytes: Encoding.ASCII.GetBytes("ab"))),
    ("extra byte stream", Check(bytes: Encoding.ASCII.GetBytes("abcd"))),
};
foreach (var (name, accepted) in badEnvelopes)
{
    if (accepted)
    {
        Console.Error.WriteLine("FAIL: synthetic envelope accepted " + name);
        return 1;
    }
}
// A missing body must not be mistaken for the default synthetic fixture.
if (PageTransferIntegrity.VerifyCompleteBytes(sessionId, pageId, 0, 3,
    "image/jpeg", abcSha256, 1024, null))
{
    Console.Error.WriteLine("FAIL: missing synthetic envelope bytes accepted");
    return 1;
}
Console.WriteLine($"PASS: 7 synthetic envelope positives + {badEnvelopes.Length + 1} fail-closed rejections");
return 0;

static byte[] ReplaceAscii(byte[] source, string target, string replacement)
{
    var s = Encoding.ASCII.GetString(source);
    var index = s.IndexOf(target, StringComparison.Ordinal);
    if (index < 0) throw new InvalidOperationException("Missing test mutation anchor");
    return Encoding.ASCII.GetBytes(s[..index] + replacement + s[(index + target.Length)..]);
}

static byte[] ChangeAscii(byte[] source, int offset, char newValue)
{
    var changed = (byte[])source.Clone();
    changed[offset] = checked((byte)newValue);
    return changed;
}
