using System.Security.AccessControl;
using System.Security.Principal;
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

    private static bool CanOpen(string dir, long maxBytes = 1024, int maxPages = 2)
    {
        using var gate = DurableReceiveJournalV1.Open(dir, Session, Digest,
            1000, 2000, maxBytes, maxPages);
        return gate is not null;
    }

    private static bool AttemptConsumedReplay(string dir)
    {
        using var newJournal = Open(dir);
        return newJournal.ClaimToken(Token, 1002);
    }

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
    // The cross-platform corruption fixture tests persistence/recovery after
    // the live owner has released its read-only pins. Android's host golden
    // semantics remain unchanged; this Windows test explicitly models offline
    // attacker access, never bypasses the native LIVE pin in production.
    private static bool TamperAfterOwnerExit(
        DurableReceiveJournalV1 owner, string path, string value)
    {
        owner.Dispose();
        return Tamper(path, value);
    }

    private static bool Action(string root, DurableReceiveJournalV1 gate, string action) =>
        action switch
        {
            "INSPECT_FRESH" => Inspect(root).Status == DurableReceiveJournalV1.RecoveryStatus.Fresh,
            "CLAIM_GOOD" => gate.ClaimToken(Token, 1001),
            "CLAIM_BAD" => gate.ClaimToken(new string('b', 64), 1001),
            "CLAIM_EXPIRED" => gate.ClaimToken(Token, 2000),
            "RESTART_CLAIM" => AttemptConsumedReplay(root),
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
            "TAMPER_BLOB" => TamperAfterOwnerExit(gate, Path.Combine(root, "page-0000.blob"), "abd"),
            "TAMPER_RECEIPT" => TamperAfterOwnerExit(gate, Path.Combine(root, "page-0000.rec"), "torn"),
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

    [System.Runtime.InteropServices.DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW",
        CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLinkNative(string newName, string existingName,
        IntPtr securityAttributes);

    private static string[] AliasGoldenCase(string id)
    {
        var golden = GoldenPath() ?? throw new InvalidOperationException("Missing canonical trace fixture");
        var path = Path.Combine(Path.GetDirectoryName(golden)!,
            "private-root-alias-v1.tsv");
        var rows = File.ReadAllLines(path, Encoding.ASCII)
            .Where(x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith('#'))
            .Select(x => x.Split('\t')).ToArray();
        if (rows.Length != 2 || rows.Any(x => x.Length != 4) ||
            rows.Select(x => x[0]).ToHashSet(StringComparer.Ordinal)
                .SetEquals(new[] { "ancestor_symlink", "external_token_hardlink" }) == false)
            throw new InvalidOperationException("Shared alias-root golden matrix is incomplete");
        return rows.Single(x => x[0] == id);
    }

    // Test fixture must actually satisfy the production owner/DACL contract:
    // inherited write grants on GitHub runner TEMP may be broader than app-private.
    private static DirectoryInfo CreatePrivateTempSubdirectory(string prefix) =>
        HardenTestDirectory(Directory.CreateTempSubdirectory(prefix));

    private static DirectoryInfo HardenTestDirectory(DirectoryInfo directory)
    {
        // Platform guard is required by CA1416 under TreatWarningsAsErrors.
        // The SelfTest is intentionally a Windows/NTFS-only physical fixture.
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Private NTFS ACL fixture needs Windows");
        var acl = directory.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var rule in acl.GetAccessRules(true, false, typeof(SecurityIdentifier))
                     .OfType<FileSystemAccessRule>().ToArray())
            acl.RemoveAccessRuleSpecific(rule);
        var user = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException("Windows current user SID unavailable");
        // A temporary directory can default to a creator-group OWNER SID
        // even after inherited ACEs are removed. Explicitly align its owner
        // with the test process, matching the real admission policy.
        acl.SetOwner(user);
        const InheritanceFlags inherit =
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        acl.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
            inherit, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None,
            AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None,
            AccessControlType.Allow));
        directory.SetAccessControl(acl);
        return directory;
    }

    private static string[] PermissionGoldenCase(string id)
    {
        var golden = GoldenPath() ?? throw new InvalidOperationException("Missing durable fixture");
        var path = Path.Combine(Path.GetDirectoryName(golden)!,
            "private-root-permission-v1.tsv");
        var rows = File.ReadAllLines(path, Encoding.ASCII)
            .Where(x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith('#'))
            .Select(x => x.Split('\t')).ToArray();
        if (rows.Length != 2 || rows.Any(x => x.Length != 3) ||
            !rows.Select(x => x[0]).ToHashSet(StringComparer.Ordinal)
                .SetEquals(new[] { "owner_private_0700", "world_writer_grant" }))
            throw new InvalidOperationException("Missing/duplicate private-root permission golden");
        return rows.Single(x => x[0] == id);
    }


    // The adversary is a REAL, separately launched OS process. Both blocked
    // and allowed outcomes are checked, avoiding false PASS from missing pwsh.
    private static bool HostileRenameFromSecondProcess(string from, string to)
    {
        static string Quote(string value) => value.Replace("'", "''", StringComparison.Ordinal);
        var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("try { [System.IO.Directory]::Move('" +
            Quote(from) + "', '" + Quote(to) + "'); exit 0 } catch { exit 17 }");
        using var process = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Missing adversarial subprocess");
        if (!process.WaitForExit(15000))
        {
            process.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Hostile rename timeout, not a PASS");
        }
        return process.ExitCode == 0;
    }


    // A separate same-SID PowerShell writer changes the NTFS FILE ID but
    // restores EXACTLY the same claim bytes. A byte/hash-only verifier has
    // no evidence that its immutable tombstone was swapped.
    private static bool HostileReplaceSameBytesFromSecondProcess(string path)
    {
        static string Quote(string s) => s.Replace("'", "''", StringComparison.Ordinal);
        var safe = Quote(path);
        var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false, CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("try { $p='" + safe + "'; $old=$p+'.prior'; " +
            "[System.IO.File]::Move($p,$old); " +
            "[System.IO.File]::Copy($old,$p); " +
            "[System.IO.File]::Delete($old); exit 0 } catch { exit 17 }");
        using var attacker = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Hostile marker-swap process unavailable");
        if (!attacker.WaitForExit(15000))
        {
            attacker.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Hostile marker-swap timed out");
        }
        return attacker.ExitCode == 0;
    }

    // Same-SID adversary performs IN-PLACE byte modification, not rename.
    // The source file identity remains unchanged, so ID-only final admission
    // would accept a corrupted confirmed page. The subprocess is real OS IO.
    private static bool HostileInPlaceWriteFromSecondProcess(string path)
    {
        static string Quote(string s) => s.Replace("'", "''", StringComparison.Ordinal);
        var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false, CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("try { $p='" + Quote(path) + "'; " +
            "$f=[System.IO.File]::Open($p,[System.IO.FileMode]::Open," +
            "[System.IO.FileAccess]::Write,[System.IO.FileShare]::ReadWrite); " +
            "try { $b=[System.Text.Encoding]::ASCII.GetBytes('BAD'); " +
            "$f.Position=0; $f.Write($b,0,$b.Length); $f.Flush($true) } " +
            "finally { $f.Dispose() }; exit 0 } catch { exit 17 }");
        using var child = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Hostile in-place writer unavailable");
        if (!child.WaitForExit(15000))
        {
            child.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Hostile in-place writer timed out");
        }
        return child.ExitCode == 0;
    }

    // Separate SAME-SID OS process acquires FileAccess.Write BEFORE the
    // journal attempts to acquire its live READ pins. It holds the handle
    // continuously until the parent writes the release marker, then changes
    // bytes via that SAME, already-open handle and flushes.
    private static System.Diagnostics.Process StartPrePinWriter(
        string asset, string ready, string release)
    {
        static string Quote(string s) => s.Replace("'", "''", StringComparison.Ordinal);
        var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false, CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add(
            "try { $p='" + Quote(asset) + "'; " +
            "$r='" + Quote(ready) + "'; $s='" + Quote(release) + "'; " +
            "$f=[System.IO.File]::Open($p,[System.IO.FileMode]::Open," +
            "[System.IO.FileAccess]::Write,[System.IO.FileShare]::ReadWrite); " +
            "try { [System.IO.File]::WriteAllText($r,'ready'); " +
            "$got=$false; for($i=0; $i -lt 600; $i++) { " +
            "if([System.IO.File]::Exists($s)) { $got=$true; break }; " +
            "[System.Threading.Thread]::Sleep(50) }; " +
            "if(-not $got) { exit 19 }; " +
            "$b=[System.Text.Encoding]::ASCII.GetBytes('BAD'); " +
            "$f.Position=0; $f.Write($b,0,$b.Length); $f.Flush($true) } " +
            "finally { $f.Dispose() }; exit 0 } catch { exit 17 }");
        var child = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("NOT VERIFIED: writer child launch failed");
        try
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            while (clock.ElapsedMilliseconds < 15000)
            {
                if (child.HasExited)
                    throw new InvalidOperationException(
                        "NOT VERIFIED: pre-pin writer exited before ready " + child.ExitCode);
                if (File.Exists(ready))
                {
                    try
                    {
                        if (File.ReadAllText(ready, Encoding.ASCII) == "ready")
                            return child;
                    }
                    catch (IOException) { /* child has not closed marker yet */ }
                }
                System.Threading.Thread.Sleep(20);
            }
            throw new InvalidOperationException("NOT VERIFIED: pre-pin writer timed out");
        }
        catch
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit(15000);
            }
            child.Dispose();
            throw;
        }
    }

    // Actual separate same-account process plants a destination AFTER stage
    // creation. A native no-overwrite rename must refuse without modifying it.
    private static bool HostilePlantDestinationFromSecondProcess(string path)
    {
        static string Quote(string s) => s.Replace("'", "''", StringComparison.Ordinal);
        var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false, CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("try { $p='" + Quote(path) + "'; " +
            "$f=[System.IO.File]::Open($p, [System.IO.FileMode]::CreateNew, " +
            "[System.IO.FileAccess]::Write, [System.IO.FileShare]::None); " +
            "try { $b=[System.Text.Encoding]::ASCII.GetBytes('ADVERSARY'); " +
            "$f.Write($b,0,$b.Length); $f.Flush($true) } finally { $f.Dispose() }; " +
            "exit 0 } catch { exit 17 }");
        using var child = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Hostile destination process missing");
        if (!child.WaitForExit(15000))
        {
            child.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Hostile destination process timed out");
        }
        return child.ExitCode == 0;
    }

    private static string[] KilledWriterGolden()
    {
        var canonical = GoldenPath() ?? throw new InvalidOperationException("Missing golden base");
        var path = Path.Combine(Path.GetDirectoryName(canonical)!, "crash-orphan-v1.tsv");
        var rows = File.ReadAllLines(path, Encoding.ASCII)
            .Where(x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith('#'))
            .Select(x => x.Split('\t')).ToArray();
        if (rows.Length != 1 || rows[0].Length != 4 ||
            rows[0][0] != "killed_external_stage_writer")
            throw new InvalidOperationException("Missing/duplicate killed-writer fixture");
        return rows[0];
    }

    private static bool HostileWriterDiesAfterStage(string root)
    {
        var stage = Path.Combine(root, "stage-0000.tmp").Replace("'", "''",
            StringComparison.Ordinal);
        var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("try { [System.IO.File]::WriteAllText('" + stage +
            "', 'partial'); [System.Diagnostics.Process]::GetCurrentProcess().Kill(); " +
            "exit 0 } catch { exit 19 }");
        using var child = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to spawn external writer");
        if (!child.WaitForExit(15000))
        {
            child.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Killed-writer subprocess timed out");
        }
        return child.ExitCode != 0 && File.Exists(Path.Combine(root, "stage-0000.tmp"));
    }

    // This executable is the REAL JOURNAL OWNER in a separate OS process.
    // A supervising SelfTest parent kills its process at a deterministic,
    // signaled checkpoint. A callback throwing is not a process crash.
    internal static int RunJournalOwnerChild(string[] args)
    {
        if (args.Length != 4 || args[0] != "--journal-owner-crash-child" ||
            args[1] is not ("normal" or "stage-prefix" or "after-rename"))
            return 64;
        try
        {
            using var journal = Open(args[2]);
            if (!journal.ClaimToken(Token, 1001)) return 65;
            if (args[1] != "normal")
            {
                void SignalAndBlock()
                {
                    using (var stream = new FileStream(args[3], FileMode.CreateNew,
                        FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                    {
                        var markerBytes = Encoding.ASCII.GetBytes("ready:" + args[1]);
                        stream.Write(markerBytes);
                        stream.Flush(flushToDisk: true);
                    }
                    // A live journal with open handles must be killed by the
                    // parent process, never by a synthetic IOException.
                    System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);
                    throw new InvalidOperationException("Unreachable crash-owner checkpoint");
                }
                if (args[1] == "stage-prefix")
                    journal.AfterStagePrefixWrittenForTest = SignalAndBlock;
                else
                    journal.AfterBlobRenamedForTest = SignalAndBlock;
            }
            return journal.Commit(Wire(Page0, 0), Body, 1002) ? 0 : 66;
        }
        catch (Exception)
        {
            return 67;
        }
    }

    private static bool RealJournalOwnerKillAndRestart(string phase)
    {
        string root = CreatePrivateTempSubdirectory("escanner-real-owner-").FullName;
        string signal = Path.Combine(Path.GetTempPath(),
            "escanner-owner-ready-" + Guid.NewGuid().ToString("N") + ".signal");
        System.Diagnostics.Process? owner = null;
        try
        {
            // Child executes ONLY RunJournalOwnerChild instead of re-entering
            // the entire suite. This is the same .NET test binary, same SID,
            // same app-private journal implementation, and an independent PID.
            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add(typeof(DurableReceiveJournalSelfTest).Assembly.Location);
            psi.ArgumentList.Add("--journal-owner-crash-child");
            psi.ArgumentList.Add(phase);
            psi.ArgumentList.Add(root);
            psi.ArgumentList.Add(signal);
            owner = System.Diagnostics.Process.Start(psi);
            if (owner is null)
            {
                Console.Error.WriteLine("NOT VERIFIED: real journal-owner child did not launch");
                return false;
            }
            if (phase == "normal")
            {
                if (!owner.WaitForExit(20000) || owner.ExitCode != 0 ||
                    Inspect(root).Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                    Inspect(root).ConfirmedPages != 1 ||
                    AttemptConsumedReplay(root))
                {
                    Console.Error.WriteLine("FAIL: independent journal-owner normal control");
                    return false;
                }
                return true;
            }
            bool signaled = false;
            var timer = System.Diagnostics.Stopwatch.StartNew();
            while (timer.ElapsedMilliseconds < 20000)
            {
                if (owner.HasExited) break;
                // The child creates its signal with FileShare.None, writes,
                // fsyncs and CLOSES it. Existence may precede Close; a sharing
                // violation is a normal transient, not an app failure.
                if (File.Exists(signal))
                {
                    try
                    {
                        if (File.ReadAllText(signal, Encoding.ASCII) == "ready:" + phase)
                        {
                            signaled = true;
                            break;
                        }
                    }
                    catch (IOException) { /* producer still holds the signal file */ }
                }
                System.Threading.Thread.Sleep(20);
            }
            if (!signaled || owner.HasExited)
            {
                Console.Error.WriteLine("NOT VERIFIED: real owner checkpoint absent: " + phase);
                return false;
            }
            // Actually terminate the process that owns the active journal
            // and wait for the OS to release its root/ancestor/file handles.
            owner.Kill(entireProcessTree: true);
            if (!owner.WaitForExit(15000) || owner.ExitCode == 0)
            {
                Console.Error.WriteLine("NOT VERIFIED: journal owner not killed: " + phase);
                return false;
            }

            string stage = Path.Combine(root, "stage-0000.tmp");
            string blob = Path.Combine(root, "page-0000.blob");
            string receipt = Path.Combine(root, "page-0000.rec");
            bool expectedFiles = phase switch
            {
                "stage-prefix" => File.Exists(stage) && new FileInfo(stage).Length == 1 &&
                    !File.Exists(blob) && !File.Exists(receipt),
                "after-rename" => !File.Exists(stage) && File.Exists(blob) &&
                    File.ReadAllBytes(blob).AsSpan().SequenceEqual(Body) &&
                    !File.Exists(receipt),
                _ => false
            };
            if (!expectedFiles ||
                Inspect(root).Status != DurableReceiveJournalV1.RecoveryStatus.Poisoned ||
                AttemptConsumedReplay(root))
            {
                Console.Error.WriteLine(
                    "FAIL: owner-kill " + phase +
                    " failed durable orphan/poison/replay assertions" +
                    " stageBytes=" + (File.Exists(stage) ? new FileInfo(stage).Length : -1) +
                    " blobBytes=" + (File.Exists(blob) ? new FileInfo(blob).Length : -1));
                return false;
            }
            Console.WriteLine("PASS: REAL journal-owner PID killed at " + phase +
                "; read-only restart POISONED and token replay denied");
            return true;
        }
        finally
        {
            if (owner is not null)
            {
                if (!owner.HasExited)
                {
                    owner.Kill(entireProcessTree: true);
                    if (!owner.WaitForExit(15000))
                        throw new InvalidOperationException("Journal owner did not terminate");
                }
                owner.Dispose();
            }
            if (File.Exists(signal)) File.Delete(signal);
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
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
            string root = CreatePrivateTempSubdirectory("escanner-receipt-").FullName;
            try
            {
                using var gate = Open(root);
                for (int i = 0; i < events.Length; i++)
                {
                    bool pass = Action(root, gate, events[i]);
                    if ((pass ? "A" : "R") != expectations[i])
                    {
                        Console.Error.WriteLine("FAIL: " + fields[0] + " action " + events[i] +
                            " native-stage=" + (gate.LastNativeFailureStage ?? "none"));
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
        if (scenarios != 37 || actions != 90)
        {
            Console.Error.WriteLine("FAIL: incomplete durable receipt golden scenarios");
            return false;
        }


        // Test-FIRST RED: prior Open() only sampled a directory file ID and
        // released its handle. An external same-user process could rename that
        // authenticated root and substitute a different path afterward.
        string pinnedRoot = CreatePrivateTempSubdirectory("escanner-pin-").FullName;
        string movedRoot = pinnedRoot + ".outside";
        try
        {
            var journal = Open(pinnedRoot);
            try
            {
                if (HostileRenameFromSecondProcess(pinnedRoot, movedRoot) ||
                    !Directory.Exists(pinnedRoot) || Directory.Exists(movedRoot))
                {
                    Console.Error.WriteLine(
                        "FAIL: hostile subprocess renamed OPEN Windows private root");
                    return false;
                }
            }
            finally
            {
                // Test compiles against the pre-fix implementation (RED)
                // while verifying that the GREEN implementation is IDisposable.
                ((object)journal as IDisposable)?.Dispose();
            }
            // A blocked subprocess alone is not evidence: prove that this
            // same hostile process CAN rename once our handle is released.
            if (!HostileRenameFromSecondProcess(pinnedRoot, movedRoot) ||
                Directory.Exists(pinnedRoot) || !Directory.Exists(movedRoot))
            {
                Console.Error.WriteLine(
                    "FAIL: positive-control adversary could not rename after release");
                return false;
            }
            Console.WriteLine(
                "PASS: pinned Windows directory denies separate-process rename until dispose");
        }
        finally
        {
            if (Directory.Exists(movedRoot) && !Directory.Exists(pinnedRoot))
                Directory.Move(movedRoot, pinnedRoot);
            if (Directory.Exists(pinnedRoot))
                Directory.Delete(pinnedRoot, recursive: true);
        }


        // RED: the root HANDLE alone does not authorize a path through an
        // ancestor that an independent writer can rename. A real same-user
        // process attempts the rename while the leaf journal is OPEN. The
        // same process MUST be able to rename after deterministic Dispose,
        // proving that a blocked attack is not an unavailable-process false PASS.
        string parentPinFixture = CreatePrivateTempSubdirectory("escanner-parent-pin-").FullName;
        string parentNode = Path.Combine(parentPinFixture, "parent");
        string movedParent = Path.Combine(parentPinFixture, "parent.moved");
        try
        {
            string nestedRoot = Path.Combine(parentNode, "session");
            HardenTestDirectory(Directory.CreateDirectory(nestedRoot));
            using (var active = Open(nestedRoot))
            {
                if (HostileRenameFromSecondProcess(parentNode, movedParent) ||
                    !Directory.Exists(nestedRoot) || Directory.Exists(movedParent))
                {
                    Console.Error.WriteLine(
                        "FAIL: hostile subprocess renamed ANCESTOR of an OPEN private root");
                    return false;
                }
                if (!active.ClaimToken(Token, 1001))
                {
                    Console.Error.WriteLine("FAIL: live pinned journal lost claimed token");
                    return false;
                }
            }
            if (!HostileRenameFromSecondProcess(parentNode, movedParent) ||
                Directory.Exists(parentNode) || !Directory.Exists(movedParent))
            {
                Console.Error.WriteLine("FAIL: ancestor rename positive control after Dispose");
                return false;
            }
            Console.WriteLine(
                "PASS: pinned Windows ancestor denies external rename until Dispose");
        }
        finally
        {
            if (Directory.Exists(movedParent) && !Directory.Exists(parentNode))
                Directory.Move(movedParent, parentNode);
            if (Directory.Exists(parentPinFixture))
                Directory.Delete(parentPinFixture, recursive: true);
        }

        // RED: a secure leaf below an attacker-writable ancestor is not a
        // private path. Run icacls in a SEPARATE Windows OS process to grant
        // Everyone write on the PARENT ONLY. The child is DACL-protected, so
        // leaf-only admission misses the ancestor poisoning.
        string unsafeParent = CreatePrivateTempSubdirectory("escanner-hostile-parent-").FullName;
        try
        {
            string protectedChild = Path.Combine(unsafeParent, "private-session");
            HardenTestDirectory(Directory.CreateDirectory(protectedChild));
            if (!CanOpen(protectedChild))
            {
                Console.Error.WriteLine("FAIL: private child positive control did not open");
                return false;
            }
            using var alreadyOpen = Open(protectedChild);
            var hostileAcl = new System.Diagnostics.ProcessStartInfo("icacls.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            hostileAcl.ArgumentList.Add(unsafeParent);
            hostileAcl.ArgumentList.Add("/grant");
            hostileAcl.ArgumentList.Add("*S-1-1-0:(W)");
            using var hostileProcess = System.Diagnostics.Process.Start(hostileAcl);
            if (hostileProcess is null || !hostileProcess.WaitForExit(15000) ||
                hostileProcess.ExitCode != 0)
            {
                Console.Error.WriteLine("NOT VERIFIED: ancestor DACL hostile process unavailable");
                return false;
            }
            if (CanOpen(protectedChild) || alreadyOpen.ClaimToken(Token, 1001) ||
                Inspect(protectedChild).Status != DurableReceiveJournalV1.RecoveryStatus.Poisoned)
            {
                Console.Error.WriteLine(
                    "FAIL: hostile ancestor NTFS DACL admitted secure child root");
                return false;
            }
            Console.WriteLine("PASS: separate-process hostile ancestor DACL rejected");
        }
        finally { Directory.Delete(unsafeParent, recursive: true); }

        // TEST-FIRST RED. The immutable claim's bytes and SHA still match,
        // but an independent same-SID process replaced its NTFS file identity.
        // No nondeterministic race or privileged account is required.
        string replacedClaimRoot =
            CreatePrivateTempSubdirectory("escanner-claim-id-swap-").FullName;
        try
        {
            using var active = Open(replacedClaimRoot);
            if (!active.ClaimToken(Token, 1001))
            {
                Console.Error.WriteLine("FAIL: claim-swap positive control failed");
                return false;
            }
            string marker = Path.Combine(replacedClaimRoot, "token.claim");
            byte[] original = File.ReadAllBytes(marker);
            if (!HostileReplaceSameBytesFromSecondProcess(marker) ||
                !File.ReadAllBytes(marker).AsSpan().SequenceEqual(original) ||
                Directory.EnumerateFileSystemEntries(replacedClaimRoot).Count() != 1)
            {
                Console.Error.WriteLine(
                    "NOT VERIFIED: separate-process exact-byte NTFS marker swap not prepared");
                return false;
            }
            if (active.Commit(Wire(Page0, 0), Body, 1002))
            {
                Console.Error.WriteLine(
                    "FAIL: same-bytes hostile token.claim identity swap admitted a page");
                return false;
            }
            Console.WriteLine(
                "PASS: replaced same-bytes token.claim denied by live journal");
        }
        finally { Directory.Delete(replacedClaimRoot, recursive: true); }

        // TEST-FIRST RED: a second same-SID process swaps a previously
        // CONFIRMED blob or receipt for a different NTFS inode containing
        // exactly identical bytes. Hash-chain and read-only recovery still
        // match; only the LIVE journal may pin the original file identities.
        foreach (string assetName in new[] { "page-0000.blob", "page-0000.rec" })
        {
            string root = CreatePrivateTempSubdirectory("escanner-page-id-swap-").FullName;
            try
            {
                using var live = Open(root);
                if (!live.ClaimToken(Token, 1001) ||
                    !live.Commit(Wire(Page0, 0), Body, 1002))
                {
                    Console.Error.WriteLine("FAIL: page-id-swap positive control incomplete");
                    return false;
                }
                string asset = Path.Combine(root, assetName);
                byte[] original = File.ReadAllBytes(asset);
                // In a LIVE journal, the confirmed page's READ-only pin
                // denies DELETE (rename) as well as WRITE, even when bytes
                // would remain unchanged. The attacker is a real child PID.
                if (HostileReplaceSameBytesFromSecondProcess(asset) ||
                    !File.ReadAllBytes(asset).AsSpan().SequenceEqual(original) ||
                    Directory.EnumerateFileSystemEntries(root).Count() != 3 ||
                    !live.Commit(Wire(Page1, 1), Body, 1003))
                {
                    Console.Error.WriteLine(
                        "FAIL: live prior-page " + assetName +
                        " rename was allowed or later benign page was rejected");
                    return false;
                }
                // Positive control: only AFTER disposing the owner is the
                // same independent process allowed to replace an inode.
                // Read-only recovery has no trusted pre-restart FILE ID root.
                live.Dispose();
                if (!HostileReplaceSameBytesFromSecondProcess(asset) ||
                    !File.ReadAllBytes(asset).AsSpan().SequenceEqual(original) ||
                    Inspect(root).Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                    Inspect(root).ConfirmedPages != 2)
                {
                    Console.Error.WriteLine(
                        "NOT VERIFIED: offline same-byte inode swap positive control failed");
                    return false;
                }
            }
            finally { Directory.Delete(root, recursive: true); }
        }
        Console.WriteLine("PASS: live prior-page blob and receipt identity swaps rejected");

        // TEST-FIRST RED: after the last hash+receipt validation and NTFS
        // FILE ID checks but BEFORE Commit returns, an independent same-SID
        // PowerShell process writes different bytes to the SAME NTFS inode.
        // The existing identity-only admission lets the corruption through.
        // Guard must DENY writes for both freshly confirmed blob and receipt.
        foreach (string leaf in new[] { "page-0000.blob", "page-0000.rec" })
        {
            string root = CreatePrivateTempSubdirectory("escanner-live-write-deny-").FullName;
            try
            {
                using var journal = Open(root);
                if (!journal.ClaimToken(Token, 1001))
                {
                    Console.Error.WriteLine("FAIL: live write-deny positive claim control");
                    return false;
                }
                string asset = Path.Combine(root, leaf);
                bool attempted = false, inPlaceWriteSucceeded = false;
                journal.BeforeSuccessfulCommitReturnForTest = () =>
                {
                    attempted = true;
                    inPlaceWriteSucceeded = HostileInPlaceWriteFromSecondProcess(asset);
                };
                bool accepted = journal.Commit(Wire(Page0, 0), Body, 1002);
                if (!attempted)
                {
                    Console.Error.WriteLine(
                        "NOT VERIFIED: final-admission separate-process writer did not run");
                    return false;
                }
                if (inPlaceWriteSucceeded)
                {
                    Console.Error.WriteLine("FAIL: same-SID in-place " + leaf +
                        " overwrite admitted at final live journal boundary" +
                        " commitReturned=" + accepted);
                    return false;
                }
                if (!accepted ||
                    Inspect(root).Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                    Inspect(root).ConfirmedPages != 1)
                {
                    Console.Error.WriteLine("FAIL: benign committed page was not recoverable");
                    return false;
                }
                // Outside the LIVE instance's lifetime, this SID can write.
                // This is a positive control proving the writer is real and
                // protection is scoped, NOT permanent Windows ACL isolation.
                journal.Dispose();
                if (!HostileInPlaceWriteFromSecondProcess(asset) ||
                    Inspect(root).Status != DurableReceiveJournalV1.RecoveryStatus.Poisoned)
                {
                    Console.Error.WriteLine(
                        "NOT VERIFIED: released file write/poison positive control failed");
                    return false;
                }
            }
            finally { Directory.Delete(root, recursive: true); }
        }
        Console.WriteLine(
            "PASS: real same-SID in-place blob and receipt writes denied by LIVE journal pins");

        // Test-first admission contract: an adversary has a LIVE WRITE
        // HANDLE to a currently valid blob or receipt BEFORE any READ pin.
        // If it is impossible to pin *both*, Commit must fail closed. The
        // child remains alive throughout the admission, then proves its
        // already-open handle could write and alter bytes after rejection.
        foreach (string leaf in new[] { "page-0000.blob", "page-0000.rec" })
        {
            string root = CreatePrivateTempSubdirectory("escanner-prepin-write-").FullName;
            string marker = Path.Combine(Path.GetTempPath(),
                "escanner-prepin-ready-" + Guid.NewGuid().ToString("N") + ".tmp");
            string release = marker + ".release";
            System.Diagnostics.Process? hostile = null;
            bool started = false;
            try
            {
                using var journal = Open(root);
                if (!journal.ClaimToken(Token, 1001))
                {
                    Console.Error.WriteLine("FAIL: pre-pin owner claim positive control");
                    return false;
                }
                string asset = Path.Combine(root, leaf);
                journal.BeforeLivePagePinsForTest = () =>
                {
                    hostile = StartPrePinWriter(asset, marker, release);
                    started = true;
                    if (hostile.HasExited || !File.Exists(asset))
                        throw new InvalidOperationException(
                            "NOT VERIFIED: pre-pin attacker did not remain alive");
                };
                bool accepted = journal.Commit(Wire(Page0, 0), Body, 1002);
                string expectedStage = leaf.EndsWith(".blob", StringComparison.Ordinal)
                    ? "blob-pin" : "receipt-pin";
                if (!started || hostile is null || hostile.HasExited ||
                    accepted || journal.LastNativeFailureStage != expectedStage ||
                    journal.Commit(Wire(Page1, 1), Body, 1003))
                {
                    Console.Error.WriteLine("FAIL: earlier same-SID WRITE handle " + leaf +
                        " breached fail-closed pin admission" +
                        " commit=" + accepted +
                        " nativeStage=" + journal.LastNativeFailureStage);
                    return false;
                }
                // Parent now asks the STILL-LIVE adversary to use its
                // already-open WRITE handle; it does not get to open a new
                // handle after the failed pin admission.
                File.WriteAllText(release, "release", Encoding.ASCII);
                if (!hostile.WaitForExit(15000) || hostile.ExitCode != 0 ||
                    File.ReadAllBytes(asset).AsSpan(0, 3).SequenceEqual(Body) ||
                    Inspect(root).Status != DurableReceiveJournalV1.RecoveryStatus.Poisoned ||
                    AttemptConsumedReplay(root))
                {
                    Console.Error.WriteLine("FAIL: pre-pin writer " + leaf +
                        " did not mutate bytes or recovery failed to detect corruption");
                    return false;
                }
            }
            finally
            {
                if (hostile is not null)
                {
                    if (!hostile.HasExited)
                    {
                        hostile.Kill(entireProcessTree: true);
                        hostile.WaitForExit(15000);
                    }
                    hostile.Dispose();
                }
                if (File.Exists(marker)) File.Delete(marker);
                if (File.Exists(release)) File.Delete(release);
                if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
            }
        }
        Console.WriteLine(
            "PASS: REAL pre-pin same-SID WRITE handle denied for blob and receipt; " +
            "post-rejection corruption detected on read-only restart");

        // SYNCHRONIZED TEST-FIRST RED. A REAL separate same-SID PowerShell
        // process replaces the just-flushed stage file *before* the old code
        // obtains its first file-ID. The attacker writes byte-identical data.
        // Pre-fix commit incorrectly trusts the new inode and confirms page 0.
        string stageSwapRoot = CreatePrivateTempSubdirectory("escanner-stage-window-").FullName;
        try
        {
            using var live = Open(stageSwapRoot);
            if (!live.ClaimToken(Token, 1001))
            {
                Console.Error.WriteLine("FAIL: live stage-race positive control claim failed");
                return false;
            }
            bool hostileRan = false;
            live.AfterStageCreatedForAdversarialTest = () =>
            {
                string stagePath = Path.Combine(stageSwapRoot, "stage-0000.tmp");
                if (!HostileReplaceSameBytesFromSecondProcess(stagePath) ||
                    !File.ReadAllBytes(stagePath).AsSpan().SequenceEqual(Body) ||
                    Directory.EnumerateFileSystemEntries(stageSwapRoot).Count() != 2)
                    throw new InvalidOperationException(
                        "NOT VERIFIED: external live-stage swap failed positive controls");
                hostileRan = true;
            };
            if (live.Commit(Wire(Page0, 0), Body, 1002))
            {
                Console.Error.WriteLine(
                    "FAIL: hostile same-bytes in-flight stage inode swap accepted a page");
                return false;
            }
            if (!hostileRan)
            {
                Console.Error.WriteLine("NOT VERIFIED: external stage swap did not execute");
                return false;
            }
            Console.WriteLine(
                "PASS: synchronized external stage inode swap rejected BEFORE page confirmation");
        }
        finally { Directory.Delete(stageSwapRoot, recursive: true); }

        // Real independent OS adversary creates a previously absent blob
        // destination after the scanner has durably created its stage. The
        // source HANDLE rename MUST fail (ReplaceIfExists=FALSE) and preserve
        // the attacker's existing bytes without creating a false receipt.
        string plantedDestinationRoot =
            CreatePrivateTempSubdirectory("escanner-no-overwrite-").FullName;
        try
        {
            using var live = Open(plantedDestinationRoot);
            if (!live.ClaimToken(Token, 1001))
            {
                Console.Error.WriteLine("FAIL: no-overwrite positive token control");
                return false;
            }
            bool attackerRan = false;
            string destination = Path.Combine(plantedDestinationRoot, "page-0000.blob");
            live.AfterStageCreatedForAdversarialTest = () =>
            {
                if (!HostilePlantDestinationFromSecondProcess(destination) ||
                    File.ReadAllText(destination, Encoding.ASCII) != "ADVERSARY")
                    throw new InvalidOperationException(
                        "NOT VERIFIED: hostile destination create positive control failed");
                attackerRan = true;
            };
            if (live.Commit(Wire(Page0, 0), Body, 1002) || !attackerRan ||
                File.ReadAllText(destination, Encoding.ASCII) != "ADVERSARY" ||
                File.Exists(Path.Combine(plantedDestinationRoot, "page-0000.rec")) ||
                Inspect(plantedDestinationRoot).Status !=
                    DurableReceiveJournalV1.RecoveryStatus.Poisoned)
            {
                Console.Error.WriteLine(
                    "FAIL: native rename overwrote hostile destination or committed receipt");
                return false;
            }
            Console.WriteLine(
                "PASS: real separate-process destination collision preserved no-overwrite");
        }
        finally { Directory.Delete(plantedDestinationRoot, recursive: true); }

        // Deterministic SYNTHETIC ERROR_DISK_FULL fault: the journal's own
        // write handle writes one byte and throws a Windows-style IOException
        // before completing the stage. This is NOT physical disk ENOSPC.
        string injectedDiskFullRoot =
            CreatePrivateTempSubdirectory("escanner-injected-diskfull-").FullName;
        try
        {
            using var gate = Open(injectedDiskFullRoot);
            if (!gate.ClaimToken(Token, 1001))
            {
                Console.Error.WriteLine("FAIL: simulated diskfull positive claim failed");
                return false;
            }
            bool injected = false;
            gate.AfterStagePrefixWrittenForTest = () =>
            {
                injected = true;
                throw new IOException("synthetic ERROR_DISK_FULL test fault",
                    unchecked((int)0x80070070));
            };
            if (gate.Commit(Wire(Page0, 0), Body, 1002) || !injected ||
                !File.Exists(Path.Combine(injectedDiskFullRoot, "stage-0000.tmp")) ||
                new FileInfo(Path.Combine(injectedDiskFullRoot, "stage-0000.tmp")).Length != 1 ||
                File.Exists(Path.Combine(injectedDiskFullRoot, "page-0000.blob")) ||
                File.Exists(Path.Combine(injectedDiskFullRoot, "page-0000.rec")) ||
                Inspect(injectedDiskFullRoot).Status !=
                    DurableReceiveJournalV1.RecoveryStatus.Poisoned ||
                AttemptConsumedReplay(injectedDiskFullRoot))
            {
                Console.Error.WriteLine(
                    "FAIL: injected partial-stage ERROR_DISK_FULL was not fail-closed");
                return false;
            }
            Console.WriteLine(
                "PASS: synthetic diskfull after one stage byte poisons read-only restart");
        }
        finally { Directory.Delete(injectedDiskFullRoot, recursive: true); }

        // Same common golden row as Android JVM test. The attacking writer is
        // a real independent Windows process terminated after emitting an
        // orphan staging record. Not a low-disk/power-cut simulation.
        string killedRoot = CreatePrivateTempSubdirectory("escanner-kill-").FullName;
        try
        {
            using var journal = Open(killedRoot);
            if (!journal.ClaimToken(Token, 1001) ||
                !HostileWriterDiesAfterStage(killedRoot))
            {
                Console.Error.WriteLine("FAIL: real killed-writer fixture did not execute");
                return false;
            }
            var goldenKilled = KilledWriterGolden();
            var recovered = Inspect(killedRoot).Status.ToString().ToUpperInvariant();
            var next = journal.Commit(Wire(Page0, 0), Body, 1002)
                ? "ACCEPT" : "REJECT";
            var presence = File.Exists(Path.Combine(killedRoot, "stage-0000.tmp"))
                ? "PRESENT" : "ABSENT";
            if (recovered != goldenKilled[1] || next != goldenKilled[2] ||
                presence != goldenKilled[3] || AttemptConsumedReplay(killedRoot))
            {
                Console.Error.WriteLine("FAIL: killed external writer reopened poisoned journal");
                return false;
            }
            Console.WriteLine(
                "PASS: externally killed writer leaves orphan and poisons restart");
        }
        finally { Directory.Delete(killedRoot, recursive: true); }

        // Separate OS PROCESS mutates the DACL; the adapter must refuse an
        // attacker-writable NTFS directory even when its path/inode is stable.
        // This is an ACL admission fixture, NOT an exhaustive TOCTOU proof.
        string aclRoot = CreatePrivateTempSubdirectory("escanner-acl-").FullName;
        try
        {
            var secure = PermissionGoldenCase("owner_private_0700");
            bool secureOpen = CanOpen(aclRoot);
            if ((secureOpen ? "ACCEPT" : "REJECT") != secure[1] ||
                Inspect(aclRoot).Status.ToString().ToUpperInvariant() != secure[2])
            {
                Console.Error.WriteLine("FAIL: secure owner-only NTFS root rejected");
                return false;
            }
            var psi = new System.Diagnostics.ProcessStartInfo("icacls.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add(aclRoot);
            psi.ArgumentList.Add("/grant");
            psi.ArgumentList.Add("*S-1-1-0:(W)"); // World SID: write
            using var attacker = System.Diagnostics.Process.Start(psi);
            if (attacker is null || !attacker.WaitForExit(15000) || attacker.ExitCode != 0)
            {
                Console.Error.WriteLine("NOT VERIFIED: hostile icacls process failed");
                return false;
            }
            var hostile = PermissionGoldenCase("world_writer_grant");
            bool hostileOpen = CanOpen(aclRoot);
            if ((hostileOpen ? "ACCEPT" : "REJECT") != hostile[1] ||
                Inspect(aclRoot).Status.ToString().ToUpperInvariant() != hostile[2])
            {
                Console.Error.WriteLine("FAIL: world-writable NTFS DACL reached private root");
                return false;
            }
            Console.WriteLine("PASS: separate-process hostile NTFS DACL rejected");
        }
        finally { Directory.Delete(aclRoot, recursive: true); }

        string privateRoot = CreatePrivateTempSubdirectory("escanner-dir-").FullName;
        try
        {
            string badFile = Path.Combine(privateRoot, "file.txt");
            File.WriteAllText(badFile, "not a directory");
            if (CanOpen(badFile) ||
                CanOpen(Path.Combine(privateRoot, "missing")) ||
                CanOpen(privateRoot, DurableReceiveJournalV1.MaxStageBytes + 1))
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
                if (CanOpen(link))
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

        string orphanRoot = CreatePrivateTempSubdirectory("escanner-orphan-start-").FullName;
        try
        {
            string orphan = Path.Combine(orphanRoot, "orphan.tmp");
            File.WriteAllText(orphan, "partial", Encoding.ASCII);
            using var gate = Open(orphanRoot);
            if (gate.ClaimToken(Token, 1001) ||
                Inspect(orphanRoot).Status != DurableReceiveJournalV1.RecoveryStatus.Poisoned)
            {
                Console.Error.WriteLine("FAIL: pre-existing orphan unexpectedly granted token");
                return false;
            }
            File.Delete(orphan);
            if (gate.ClaimToken(Token, 1002))
            {
                Console.Error.WriteLine("FAIL: tampered folder revived previously denied token");
                return false;
            }
        }
        finally { Directory.Delete(orphanRoot, recursive: true); }

        string raceRoot = CreatePrivateTempSubdirectory("escanner-claim-race-").FullName;
        try
        {
            var gates = Enumerable.Range(0, 24).Select(_ => Open(raceRoot)).ToArray();
            try
            {
                int admitted = 0;
                System.Threading.Tasks.Parallel.ForEach(gates, gate =>
                {
                    if (gate.ClaimToken(Token, 1001))
                        System.Threading.Interlocked.Increment(ref admitted);
                });
                if (admitted != 1 ||
                    Inspect(raceRoot).Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                    AttemptConsumedReplay(raceRoot))
                {
                    Console.Error.WriteLine("FAIL: durable CREATE_NEW token replay race");
                    return false;
                }
            }
            finally { foreach (var gate in gates) gate.Dispose(); }
        }
        finally { Directory.Delete(raceRoot, recursive: true); }

        // A symlink in an ANCESTOR is different from the existing root-link test.
        // Windows symlink privilege is runner-dependent; absent privilege means NOT VERIFIED.
        string ancestorParent = CreatePrivateTempSubdirectory("escanner-parent-").FullName;
        try
        {
            var real = Path.Combine(ancestorParent, "real");
            var sessionDir = Path.Combine(real, "session");
            HardenTestDirectory(Directory.CreateDirectory(sessionDir));
            var alias = Path.Combine(ancestorParent, "alias");
            bool made = false;
            try
            {
                Directory.CreateSymbolicLink(alias, real);
                made = true;
                var expected = AliasGoldenCase("ancestor_symlink");
                var actualOpen = CanOpen(Path.Combine(alias, "session"))
                    ? "ACCEPT" : "REJECT";
                var actualRecovery = Inspect(Path.Combine(alias, "session"))
                    .Status.ToString().ToUpperInvariant();
                if (!CanOpen(sessionDir) ||
                    actualOpen != expected[1] || actualRecovery != expected[2])
                {
                    Console.Error.WriteLine("FAIL: symlinked ancestor reached private root");
                    return false;
                }
                Console.WriteLine("PASS: Windows parent-directory symlink rejected");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("NOT VERIFIED: Windows parent symlink privilege unavailable");
            }
            catch (IOException)
            {
                Console.WriteLine("NOT VERIFIED: Windows parent symlink creation unavailable");
            }
            finally { if (made) Directory.Delete(alias); }
        }
        finally { Directory.Delete(ancestorParent, recursive: true); }

        // A token-claim with an outside hardlink is an unsafe alias even when
        // its bytes have not changed yet. Windows NTFS supports this without
        // elevated privilege; failed fixture creation is NOT a PASS.
        string hardlinkRoot = CreatePrivateTempSubdirectory("escanner-hardlink-").FullName;
        string hardlinkAlias = Path.Combine(Path.GetDirectoryName(hardlinkRoot)!,
            Path.GetRandomFileName() + ".hardlink");
        try
        {
            using var journal = Open(hardlinkRoot);
            if (!journal.ClaimToken(Token, 1001) ||
                !CreateHardLinkNative(hardlinkAlias, Path.Combine(hardlinkRoot, "token.claim"),
                    IntPtr.Zero))
            {
                Console.Error.WriteLine("FAIL: unable to prepare NTFS hardlink admission fixture");
                return false;
            }
            var expected = AliasGoldenCase("external_token_hardlink");
            var recovery = Inspect(hardlinkRoot).Status.ToString().ToUpperInvariant();
            var actualCommit = journal.Commit(Wire(Page0, 0), Body, 1002) ?
                "ACCEPT" : "REJECT";
            if (recovery != expected[2] || actualCommit != expected[3])
            {
                Console.Error.WriteLine("FAIL: external hardlink to token.claim admitted");
                return false;
            }
            Console.WriteLine("PASS: external hardlink marker rejected before further commit");
        }
        finally
        {
            if (File.Exists(hardlinkAlias)) File.Delete(hardlinkAlias);
            Directory.Delete(hardlinkRoot, recursive: true);
        }

        // Normal independent owner subprocess is the positive control.
        // Each interrupted case launches a FRESH owner process and requires
        // actual external PID termination plus read-only restart checks.
        if (!RealJournalOwnerKillAndRestart("normal") ||
            !RealJournalOwnerKillAndRestart("stage-prefix") ||
            !RealJournalOwnerKillAndRestart("after-rename"))
            return false;

        // Real NTFS/temp-file profiling, NOT a product latency target.
        // Extended 500/1000 rounds are opt-in to avoid excessive CI load.
        var sizes = Environment.GetEnvironmentVariable("EMBASIC_ESCANNER_PERF_EXTENDED") == "1"
            ? new[] { 20, 100, 500, 1000 }
            : new[] { 20, 100 };
        foreach (int pages in sizes)
        {
            string perfRoot = CreatePrivateTempSubdirectory("escanner-perf-").FullName;
            try
            {
                // The same process really holds two read-only NTFS handles per
                // committed page. These are OS HANDLE measurements, not a
                // count inferred from code or a synthetic handle mock.
                using var current = System.Diagnostics.Process.GetCurrentProcess();
                int before = current.HandleCount;
                long milliseconds;
                int live;
                using (var gate = DurableReceiveJournalV1.Open(perfRoot, Session, Digest,
                    1000, 2000, 1024, pages))
                {
                    if (gate is null || !gate.ClaimToken(Token, 1001))
                    {
                        Console.Error.WriteLine("FAIL: synthetic perf session setup " + pages);
                        return false;
                    }
                    long started = System.Diagnostics.Stopwatch.GetTimestamp();
                    for (int i = 0; i < pages; i++)
                    {
                        string syntheticId = (i + 1).ToString("x8",
                            System.Globalization.CultureInfo.InvariantCulture) +
                            "-89ab-4cde-8f01-23456789abcd";
                        if (!gate.Commit(Wire(syntheticId, i), Body, 1001))
                        {
                            Console.Error.WriteLine("FAIL: synthetic perf page " + i + "/" + pages +
                                " nativeStage=" + gate.LastNativeFailureStage);
                            return false;
                        }
                    }
                    milliseconds = (long)System.Diagnostics.Stopwatch
                        .GetElapsedTime(started).TotalMilliseconds;
                    // .NET Process.HandleCount is CACHED until Refresh().
                    // Without Refresh, baseline and live samples match falsely.
                    current.Refresh();
                    live = current.HandleCount;
                    int expectedPins = checked(pages * 2);
                    // The private root/ancestor handle chain and CLR internals
                    // add bounded overhead. Refuse under-pinning or unexpected
                    // per-page native handle leaks; do not assert a global SLA.
                    int delta = live - before;
                    if (delta < expectedPins || delta > expectedPins + 128)
                    {
                        Console.Error.WriteLine("FAIL: live Windows NTFS pin handle budget " +
                            pages + " baseline=" + before + " live=" + live +
                            " expectedPins=" + expectedPins);
                        return false;
                    }
                    var recovery = DurableReceiveJournalV1.Inspect(perfRoot, Session,
                        Digest, 1000, 2000, 1024, pages);
                    if (recovery.Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                        recovery.ConfirmedPages != pages)
                    {
                        Console.Error.WriteLine("FAIL: synthetic perf receipt accounting " + pages);
                        return false;
                    }
                }
                // Dispose must release ALL page pins before the same process
                // starts its independent read-only restart inspection.
                current.Refresh();
                int after = current.HandleCount;
                if (Math.Abs(after - before) > 64)
                {
                    Console.Error.WriteLine("FAIL: Windows NTFS pin handle leak after Dispose " +
                        pages + " baseline=" + before + " after=" + after);
                    return false;
                }
                var restarted = DurableReceiveJournalV1.Inspect(perfRoot, Session,
                    Digest, 1000, 2000, 1024, pages);
                using var newJournal = DurableReceiveJournalV1.Open(perfRoot,
                    Session, Digest, 1000, 2000, 1024, pages);
                if (restarted.Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                    restarted.ConfirmedPages != pages ||
                    newJournal is null || newJournal.ClaimToken(Token, 1002))
                {
                    Console.Error.WriteLine(
                        "FAIL: Windows NTFS multi-page restart/replay after Dispose " + pages);
                    return false;
                }
                Console.WriteLine($"FOUNDATION_PERF_WINDOWS_NTFS pages={pages} " +
                    $"elapsedMs={milliseconds} syntheticBytesPerPage=3 noLatencySla=true");
                Console.WriteLine($"FOUNDATION_HANDLES_WINDOWS_NTFS pages={pages} " +
                    $"baseline={before} live={live} afterDispose={after} " +
                    $"expectedPinHandles={2 * pages} restartPages={pages} " +
                    "replayDenied=true noHandleSla=true");
            }
            finally { Directory.Delete(perfRoot, recursive: true); }
        }

        Console.WriteLine($"PASS: {scenarios} actual-file cross-platform durable receipt cases / " +
            $"{actions} decisions; private-root policy and 24-instance exclusive token race");
        return true;
    }
}
