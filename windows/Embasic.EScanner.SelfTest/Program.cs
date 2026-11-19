using System.Text;
using Embasic.EScanner.Contracts;
// Real child journal-owner mode: run exactly this physical process, bypass the
// normal synthetic suite, and let the parent test KILL the owned process.
if (args.Length > 0 && args[0] == "--journal-owner-crash-child")
    return DurableReceiveJournalSelfTest.RunJournalOwnerChild(args);

// Separate deterministic valid 12MP synthetic PNG/NTFS capability probe.
// NEVER run it as part of the 3-byte golden contract suite.
if (args.Length > 0 && args[0] == "--high-resolution-png-ntfs")
    return DurableReceiveJournalSelfTest.RunHighResolutionPngJournalTest();

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

// Exact PUBLIC byte fixtures are shared with Android/JUnit.
const string canonicalWire = "{\"protocolVersion\":1,\"sessionId\":\"01234567-89ab-4cde-8f01-23456789abcd\"," +
    "\"pageId\":\"11234567-89ab-4cde-8f01-23456789abcd\",\"order\":0,\"byteSize\":3," +
    "\"mime\":\"image/jpeg\",\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}";
var wireRoot = Directory.GetCurrentDirectory();
string? goldenPath = null;
for (var i = 0; i < 8; i++)
{
    var candidate = Path.Combine(wireRoot, "tests", "golden", "page-wire-v1.hex.tsv");
    if (File.Exists(candidate)) { goldenPath = candidate; break; }
    var parent = Directory.GetParent(wireRoot);
    if (parent is null) break;
    wireRoot = parent.FullName;
}
if (goldenPath is null)
{
    Console.Error.WriteLine("FAIL: missing cross-platform shared golden fixture");
    return 1;
}
int validWires = 0, invalidWires = 0;
var seenWires = new HashSet<string>(StringComparer.Ordinal);
foreach (var line in File.ReadAllLines(goldenPath, Encoding.ASCII))
{
    if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
    var parts = line.Split('\t');
    if (parts.Length != 3 || !seenWires.Add(parts[0]) ||
        parts[1] is not ("PASS" or "REJECT"))
    {
        Console.Error.WriteLine("FAIL: invalid shared fixture metadata");
        return 1;
    }
    byte[] bytes;
    try { bytes = Convert.FromHexString(parts[2]); }
    catch (FormatException)
    {
        Console.Error.WriteLine("FAIL: fixture must contain valid hex");
        return 1;
    }
    var parsed = PageWireV1.Parse(bytes, sessionId, 1024);
    if (parts[1] == "PASS")
    {
        validWires++;
        if (parsed is null || parsed.ProtocolVersion != 1 || parsed.ByteSize != 3 ||
            !PageWireV1.VerifyBody(parsed, 1024, abc) ||
            PageWireV1.VerifyBody(parsed, 1024, Encoding.ASCII.GetBytes("abd")) ||
            PageWireV1.VerifyBody(parsed, 1024, null) ||
            PageWireV1.Parse(Encoding.ASCII.GetBytes(parsed.CanonicalJson), sessionId, 1024)?.CanonicalJson != parsed.CanonicalJson ||
            (parts[0] is "valid_canonical" or "valid_reordered" or "valid_whitespace" && parsed.CanonicalJson != canonicalWire))
        {
            Console.Error.WriteLine("FAIL: accepted fixture changed meaning: " + parts[0]);
            return 1;
        }
    }
    else
    {
        invalidWires++;
        if (parsed is not null)
        {
            Console.Error.WriteLine("FAIL: unsafe fixture admitted: " + parts[0]);
            return 1;
        }
    }
}
if (seenWires.Count != 63 || validWires != 5 || invalidWires != 58)
{
    Console.Error.WriteLine("FAIL: truncated/altered shared fixture set");
    return 1;
}
var wireRaw = Encoding.ASCII.GetBytes(canonicalWire);
if (PageWireV1.Parse(wireRaw, sessionId, 3) is null ||
    PageWireV1.Parse(wireRaw, sessionId, 2) is not null ||
    PageWireV1.Parse(wireRaw, sessionId, 0) is not null ||
    PageWireV1.Parse(wireRaw, sessionId, -1) is not null ||
    PageWireV1.Parse(wireRaw, "21234567-89ab-4cde-8f01-23456789abcd", 1024) is not null ||
    PageWireV1.Parse(wireRaw, sessionId.ToUpperInvariant(), 1024) is not null ||
    PageWireV1.Parse(wireRaw, null, 1024) is not null ||
    PageWireV1.Parse(null, sessionId, 1024) is not null)
{
    Console.Error.WriteLine("FAIL: caller-bound session/size policy bypass");
    return 1;
}
Console.WriteLine("PASS: " + validWires + " accepted, " + invalidWires +
    " rejected shared raw-wire golden cases; trusted session/cap enforced");


{
    // All raw policy/receipt traces run from one PUBLIC cross-platform TSV.
    const string syntheticSession = "01234567-89ab-4cde-8f01-23456789abcd";
    const string syntheticPage0 = "11234567-89ab-4cde-8f01-23456789abcd";
    const string syntheticPage1 = "21234567-89ab-4cde-8f01-23456789abcd";
    const string syntheticTokenSha = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb";
    const string syntheticHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    var syntheticToken = new string('a', 64);
    var syntheticBody = Encoding.ASCII.GetBytes("abc");

    ReceiveGateV1 NewGate() => ReceiveGateV1.Open(
        syntheticSession, syntheticTokenSha, 1000, 2000, 1024, 2)
        ?? throw new InvalidOperationException("Trusted golden policy is invalid");

    byte[] Wire(string page, int order, string sid = syntheticSession, string hash = syntheticHash) =>
        Encoding.ASCII.GetBytes($"{{\"protocolVersion\":1,\"sessionId\":\"{sid}\"," +
            $"\"pageId\":\"{page}\",\"order\":{order},\"byteSize\":3," +
            $"\"mime\":\"image/jpeg\",\"sha256\":\"{hash}\"}}");

    ReceiveGateV1.Decision Action(ReceiveGateV1 gate, string name, long now) => name switch
    {
        "AUTH_GOOD" => gate.Authenticate(syntheticToken, now),
        "AUTH_BAD" => gate.Authenticate(new string('b', 64), now),
        "AUTH_UPPER" => gate.Authenticate(syntheticToken.ToUpperInvariant(), now),
        "AUTH_EMPTY" => gate.Authenticate("", now),
        "AUTH_NULL" => gate.Authenticate(null, now),
        "STAGE0" => gate.Propose(Wire(syntheticPage0, 0), syntheticBody, now),
        "STAGE0_BAD_BYTES" => gate.Propose(Wire(syntheticPage0, 0), Encoding.ASCII.GetBytes("abd"), now),
        "STAGE0_PARTIAL" => gate.Propose(Wire(syntheticPage0, 0), Encoding.ASCII.GetBytes("ab"), now),
        "STAGE0_NULL" => gate.Propose(Wire(syntheticPage0, 0), null, now),
        "STAGE0_BAD_HASH" => gate.Propose(Wire(syntheticPage0, 0, hash: new string('0', 64)), syntheticBody, now),
        "STAGE0_WRONG_SESSION" => gate.Propose(
            Wire(syntheticPage0, 0, sid: "31234567-89ab-4cde-8f01-23456789abcd"), syntheticBody, now),
        "STAGE1" => gate.Propose(Wire(syntheticPage1, 1), syntheticBody, now),
        "STAGE1_DUPID" => gate.Propose(Wire(syntheticPage0, 1), syntheticBody, now),
        "STAGE2" => gate.Propose(Wire(syntheticPage1, 2), syntheticBody, now),
        "CONFIRM_GOOD" => gate.ConfirmReread(syntheticBody, now),
        "CONFIRM_BAD" => gate.ConfirmReread(Encoding.ASCII.GetBytes("abd"), now),
        "CONFIRM_NULL" => gate.ConfirmReread(null, now),
        "CLOSE" => gate.Close(),
        _ => throw new InvalidOperationException("Unknown golden action: " + name)
    };

    var traceRoot = Directory.GetCurrentDirectory();
    string? tracePath = null;
    for (int i = 0; i < 8; i++)
    {
        var candidate = Path.Combine(traceRoot, "tests", "golden", "receive-gate-v1.tsv");
        if (File.Exists(candidate)) { tracePath = candidate; break; }
        var parent = Directory.GetParent(traceRoot);
        if (parent is null) break;
        traceRoot = parent.FullName;
    }
    if (tracePath is null)
    {
        Console.Error.WriteLine("FAIL: missing shared receive-gate-v1.tsv");
        return 1;
    }
    int traces = 0, decisions = 0;
    var names = new HashSet<string>(StringComparer.Ordinal);
    foreach (var line in File.ReadAllLines(tracePath, Encoding.ASCII))
    {
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
        var parts = line.Split('\t');
        if (parts.Length != 5 || !names.Add(parts[0]))
        {
            Console.Error.WriteLine("FAIL: duplicate or malformed receive-gate golden row");
            return 1;
        }
        var actions = parts[1].Split(',');
        var expected = parts[2].Split(',');
        if (actions.Length != expected.Length)
        {
            Console.Error.WriteLine("FAIL: truncated receive-gate fixture expectations");
            return 1;
        }
        var gate = NewGate();
        for (int i = 0; i < actions.Length; i++)
        {
            var step = actions[i].Split('@');
            if (step.Length != 2 || !long.TryParse(step[1], System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out var now))
                throw new InvalidOperationException("Invalid deterministic fixture clock");
            var actual = Action(gate, step[0], now);
            var label = actual == ReceiveGateV1.Decision.Accepted ? "A" : "R";
            if (label != expected[i])
            {
                Console.Error.WriteLine("FAIL: " + parts[0] + " step " + i +
                    " expected " + expected[i] + " got " + label);
                return 1;
            }
            decisions++;
        }
        if (gate.CurrentPhase.ToString().ToUpperInvariant() != parts[3] ||
            gate.ConfirmedPages.ToString(System.Globalization.CultureInfo.InvariantCulture) != parts[4])
        {
            Console.Error.WriteLine("FAIL: incorrect terminal receive-gate phase/count for " + parts[0]);
            return 1;
        }
        traces++;
    }
    if (traces != 38 || decisions != 95)
    {
        Console.Error.WriteLine("FAIL: incomplete shared receive-gate matrix");
        return 1;
    }
    var invalid = new ReceiveGateV1?[]
    {
        ReceiveGateV1.Open(null, syntheticTokenSha, 1000, 2000, 1024, 2),
        ReceiveGateV1.Open(syntheticSession.ToUpperInvariant(), syntheticTokenSha, 1000, 2000, 1024, 2),
        ReceiveGateV1.Open(syntheticSession, null, 1000, 2000, 1024, 2),
        ReceiveGateV1.Open(syntheticSession, syntheticTokenSha.ToUpperInvariant(), 1000, 2000, 1024, 2),
        ReceiveGateV1.Open(syntheticSession, syntheticTokenSha, -1, 2000, 1024, 2),
        ReceiveGateV1.Open(syntheticSession, syntheticTokenSha, 1000, 1000, 1024, 2),
        ReceiveGateV1.Open(syntheticSession, syntheticTokenSha, 1000, 301001, 1024, 2),
        ReceiveGateV1.Open(syntheticSession, syntheticTokenSha, 1000, 2000, 0, 2),
        ReceiveGateV1.Open(syntheticSession, syntheticTokenSha, 1000, 2000, 1024, 0),
        ReceiveGateV1.Open(syntheticSession, syntheticTokenSha, 1000, 2000, 1024, 1001)
    };
    if (invalid.Any(x => x is not null))
    {
        Console.Error.WriteLine("FAIL: invalid trusted receive-gate policy admitted");
        return 1;
    }
    var race = NewGate();
    int accepted = 0;
    System.Threading.Tasks.Parallel.For(0, 24, _ =>
    {
        if (race.Authenticate(syntheticToken, 1000) == ReceiveGateV1.Decision.Accepted)
            System.Threading.Interlocked.Increment(ref accepted);
    });
    if (accepted != 1 || race.CurrentPhase != ReceiveGateV1.Phase.Authorized)
    {
        Console.Error.WriteLine("FAIL: one-shot token concurrent replay accepted");
        return 1;
    }
    var stageRace = NewGate();
    if (stageRace.Authenticate(syntheticToken, 1000) != ReceiveGateV1.Decision.Accepted)
        return 1;
    accepted = 0;
    System.Threading.Tasks.Parallel.For(0, 20, _ =>
    {
        if (stageRace.Propose(Wire(syntheticPage0, 0), syntheticBody, 1001) ==
            ReceiveGateV1.Decision.Accepted)
            System.Threading.Interlocked.Increment(ref accepted);
    });
    if (accepted != 1 || stageRace.ConfirmReread(syntheticBody, 1002) !=
        ReceiveGateV1.Decision.Accepted || stageRace.ConfirmedPages != 1)
    {
        Console.Error.WriteLine("FAIL: concurrent staging accepted multiple pending pages");
        return 1;
    }
    Console.WriteLine($"PASS: {traces} shared receive-gate golden traces / {decisions} decisions; " +
        "10 invalid policies and two concurrent single-winner races");
}

if (!DurableReceiveJournalSelfTest.Run()) return 1;

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
