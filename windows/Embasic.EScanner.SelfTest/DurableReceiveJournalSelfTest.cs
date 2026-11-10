using System.Text;
using Embasic.EScanner.Contracts;

/// <summary>Real local Windows NTFS/temp-file tests; never a production TLS/QR/device claim.</summary>
internal static class DurableReceiveJournalSelfTest
{
    private const string Session = "01234567-89ab-4cde-8f01-23456789abcd";
    private const string Page0 = "11234567-89ab-4cde-8f01-23456789abcd";
    private const string Page1 = "21234567-89ab-4cde-8f01-23456789abcd";
    private const string Digest = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb";
    private const string Hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private static readonly byte[] Body = Encoding.ASCII.GetBytes("abc");
    private static readonly string Token = new('a', 64); // synthetic ONLY

    private static DurableReceiveJournalV1 Open(string dir) =>
        DurableReceiveJournalV1.Open(dir, Session, Digest, 1000, 2000, 1024, 2)
        ?? throw new InvalidOperationException("Valid synthetic policy rejected");

    private static DurableReceiveJournalV1.Recovery Inspect(string dir) =>
        DurableReceiveJournalV1.Inspect(dir, Session, Digest, 1000, 2000, 1024, 2);

    private static byte[] Wire(string page, int order, string sid = Session, string sha = Hash) =>
        Encoding.ASCII.GetBytes($"{{\"protocolVersion\":1,\"sessionId\":\"{sid}\"," +
            $"\"pageId\":\"{page}\",\"order\":{order},\"byteSize\":3," +
            $"\"mime\":\"image/jpeg\",\"sha256\":\"{sha}\"}}");

    private static bool Create(string path)
    {
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(Encoding.ASCII.GetBytes("orphan"));
        output.Flush(flushToDisk: true);
        return true;
    }
    private static bool Tamper(string path, string value)
    {
        File.WriteAllText(path, value, Encoding.ASCII);
        return true;
    }

    private static bool Action(string root, DurableReceiveJournalV1 gate, string action) =>
        action switch
        {
            "INSPECT_FRESH" => Inspect(root).Status == DurableReceiveJournalV1.RecoveryStatus.Fresh,
            "CLAIM_GOOD" => gate.ClaimToken(Token, 1001),
            "CLAIM_BAD" => gate.ClaimToken(new string('b', 64), 1001),
            "CLAIM_EXPIRED" => gate.ClaimToken(Token, 2000),
            "RESTART_CLAIM" => Open(root).ClaimToken(Token, 1002),
            "COMMIT0" => gate.Commit(Wire(Page0, 0), Body, 1002),
            "COMMIT1" => gate.Commit(Wire(Page1, 1), Body, 1003),
            "COMMIT2" => gate.Commit(Wire(Page1, 2), Body, 1004),
            "COMMIT0_EXPIRED" => gate.Commit(Wire(Page0, 0), Body, 2000),
            "COMMIT0_BAD_BYTES" => gate.Commit(Wire(Page0, 0), Encoding.ASCII.GetBytes("abd"), 1002),
            "COMMIT0_PARTIAL" => gate.Commit(Wire(Page0, 0), Encoding.ASCII.GetBytes("ab"), 1002),
            "COMMIT0_BAD_HASH" => gate.Commit(Wire(Page0, 0, sha: new string('0', 64)), Body, 1002),
            "COMMIT0_FOREIGN" => gate.Commit(
                Wire(Page0, 0, sid: "31234567-89ab-4cde-8f01-23456789abcd"), Body, 1002),
            "COMMIT1_DUPID" => gate.Commit(Wire(Page0, 1), Body, 1003),
            "COMMIT1_BAD_BYTES" => gate.Commit(Wire(Page1, 1), Encoding.ASCII.GetBytes("abd"), 1003),
            "TAMPER_BLOB" => Tamper(Path.Combine(root, "page-0000.blob"), "abd"),
            "TAMPER_RECEIPT" => Tamper(Path.Combine(root, "page-0000.rec"), "torn"),
            "TAMPER_CLAIM" => Tamper(Path.Combine(root, "token.claim"), "torn"),
            "ORPHAN_TEMP" => Create(Path.Combine(root, "stage-0000.tmp")),
            "ORPHAN_BLOB" => Create(Path.Combine(root, "page-0000.blob")),
            "ORPHAN_RECEIPT" => Create(Path.Combine(root, "page-0000.rec")),
            "UNKNOWN_FILE" => Create(Path.Combine(root, "unknown.file")),
            "EXTRA_GAP" => Create(Path.Combine(root, "page-0003.rec")),
            _ => throw new InvalidOperationException("Unknown journal action: " + action)
        };

    private static string? GoldenPath()
    {
        var dir = Directory.GetCurrentDirectory();
        for (int i = 0; i < 8; i++)
        {
            var candidate = Path.Combine(dir, "tests", "golden", "durable-receipt-v1.tsv");
            if (File.Exists(candidate)) return candidate;
            var parent = Directory.GetParent(dir);
            if (parent is null) break;
            dir = parent.FullName;
        }
        return null;
    }

    public static bool Run()
    {
        string? golden = GoldenPath();
        if (golden is null)
        {
            Console.Error.WriteLine("FAIL: missing exact cross-platform durable-receipt-v1.tsv");
            return false;
        }
        int scenarios = 0, actions = 0;
        var caseIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in File.ReadAllLines(golden, Encoding.ASCII))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
            var fields = line.Split('\t');
            if (fields.Length != 5 || !caseIds.Add(fields[0]))
            {
                Console.Error.WriteLine("FAIL: invalid/duplicate durable receipt fixture");
                return false;
            }
            string[] events = fields[1].Split(','), expectations = fields[2].Split(',');
            if (events.Length != expectations.Length) return false;
            string root = Directory.CreateTempSubdirectory("escanner-receipt-").FullName;
            try
            {
                var gate = Open(root);
                for (int i = 0; i < events.Length; i++)
                {
                    bool pass = Action(root, gate, events[i]);
                    if ((pass ? "A" : "R") != expectations[i])
                    {
                        Console.Error.WriteLine("FAIL: " + fields[0] + " action " + events[i]);
                        return false;
                    }
                    actions++;
                }
                var summary = Inspect(root);
                string status = summary.Status switch
                {
                    DurableReceiveJournalV1.RecoveryStatus.Fresh => "FRESH",
                    DurableReceiveJournalV1.RecoveryStatus.TokenConsumed => "TOKEN_CONSUMED",
                    _ => "POISONED"
                };
                if (status != fields[3] ||
                    summary.ConfirmedPages.ToString(System.Globalization.CultureInfo.InvariantCulture) != fields[4])
                {
                    Console.Error.WriteLine("FAIL: recovery differs: " + fields[0] +
                        " expected " + fields[3] + "/" + fields[4] + " got " +
                        status + "/" + summary.ConfirmedPages);
                    return false;
                }
                scenarios++;
            }
            finally { Directory.Delete(root, recursive: true); }
        }
        if (scenarios != 30 || actions != 64)
        {
            Console.Error.WriteLine("FAIL: incomplete durable receipt golden scenarios");
            return false;
        }

        string privateRoot = Directory.CreateTempSubdirectory("escanner-dir-").FullName;
        try
        {
            string badFile = Path.Combine(privateRoot, "file.txt");
            File.WriteAllText(badFile, "not a directory");
            if (DurableReceiveJournalV1.Open(badFile, Session, Digest, 1000, 2000, 1024, 2) is not null ||
                DurableReceiveJournalV1.Open(Path.Combine(privateRoot, "missing"), Session,
                    Digest, 1000, 2000, 1024, 2) is not null ||
                DurableReceiveJournalV1.Open(privateRoot, Session, Digest,
                    1000, 2000, DurableReceiveJournalV1.MaxStageBytes + 1, 2) is not null)
            {
                Console.Error.WriteLine("FAIL: invalid durable receipt root or cap admitted");
                return false;
            }
            // A symlink/junction test may need Windows Developer Mode; if not allowed,
            // report NOT VERIFIED instead of claiming that physical attack was tested.
            string link = Path.Combine(privateRoot, "link");
            bool linkCreated = false;
            try
            {
                Directory.CreateSymbolicLink(link, privateRoot);
                linkCreated = true;
                if (DurableReceiveJournalV1.Open(link, Session, Digest, 1000, 2000, 1024, 2) is not null)
                {
                    Console.Error.WriteLine("FAIL: Windows reparse directory admitted");
                    return false;
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("NOT VERIFIED: Windows symlink creation requires privilege");
            }
            catch (IOException)
            {
                Console.WriteLine("NOT VERIFIED: Windows symlink creation unavailable");
            }
            finally { if (linkCreated) Directory.Delete(link); }
        }
        finally { Directory.Delete(privateRoot, recursive: true); }

        string raceRoot = Directory.CreateTempSubdirectory("escanner-claim-race-").FullName;
        try
        {
            var gates = Enumerable.Range(0, 24).Select(_ => Open(raceRoot)).ToArray();
            int admitted = 0;
            System.Threading.Tasks.Parallel.ForEach(gates, gate =>
            {
                if (gate.ClaimToken(Token, 1001)) System.Threading.Interlocked.Increment(ref admitted);
            });
            if (admitted != 1 ||
                Inspect(raceRoot).Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                Open(raceRoot).ClaimToken(Token, 1002))
            {
                Console.Error.WriteLine("FAIL: durable CREATE_NEW token replay race");
                return false;
            }
        }
        finally { Directory.Delete(raceRoot, recursive: true); }

        Console.WriteLine($"PASS: {scenarios} actual-file cross-platform durable receipt cases / " +
            $"{actions} decisions; private-root policy and 24-instance exclusive token race");
        return true;
    }
}
